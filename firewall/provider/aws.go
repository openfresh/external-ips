// Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
// https://github.com/openfresh/external-ips

package provider

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/linki/instrumented_http"
	"github.com/openfresh/external-ips/firewall/inbound"
	"github.com/openfresh/external-ips/firewall/plan"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const TagNameExternalIPsPrefix = "external-ips/"
const ResourceLifecycleOwned = "owned"

// EC2API is the subset of the AWS EC2 API that we actually use.  Add methods as required. Signatures must match exactly.
type EC2API interface {
	DescribeInstances(input *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(input *ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error)
	CreateSecurityGroup(input *ec2.CreateSecurityGroupInput) (*ec2.CreateSecurityGroupOutput, error)
	AuthorizeSecurityGroupIngress(input *ec2.AuthorizeSecurityGroupIngressInput) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupIngress(input *ec2.RevokeSecurityGroupIngressInput) (*ec2.RevokeSecurityGroupIngressOutput, error)
	DeleteSecurityGroup(input *ec2.DeleteSecurityGroupInput) (*ec2.DeleteSecurityGroupOutput, error)
	CreateTags(input *ec2.CreateTagsInput) (*ec2.CreateTagsOutput, error)
	DescribeInstanceAttribute(input *ec2.DescribeInstanceAttributeInput) (*ec2.DescribeInstanceAttributeOutput, error)
	ModifyInstanceAttribute(input *ec2.ModifyInstanceAttributeInput) (*ec2.ModifyInstanceAttributeOutput, error)
}

// AWSProvider is an implementation of Provider for AWS EC2.
type AWSProvider struct {
	client                    EC2API
	kubeClient                kubernetes.Interface
	vpcID                     string
	clusterName               string
	mapInstanceIdToProviderId map[string]string
	dryRun                    bool
}

// AWSConfig contains configuration to create a new AWS provider.
type AWSConfig struct {
	AssumeRole string
	DryRun     bool
}

// awsInstanceRegMatch represents Regex Match for AWS instance.
var awsInstanceRegMatch = regexp.MustCompile("^i-[^/]*$")

func mapToAWSInstanceID(providerID string) (string, error) {
	s := providerID

	if !strings.HasPrefix(s, "aws://") {
		// Assume a bare aws volume id (vol-1234...)
		// Build a URL with an empty host (AZ)
		s = "aws://" + "/" + "/" + s
	}
	url, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("Invalid instance name (%s): %v", providerID, err)
	}
	if url.Scheme != "aws" {
		return "", fmt.Errorf("Invalid scheme for AWS instance (%s)", providerID)
	}

	awsID := ""
	tokens := strings.Split(strings.Trim(url.Path, "/"), "/")
	if len(tokens) == 1 {
		// instanceId
		awsID = tokens[0]
	} else if len(tokens) == 2 {
		// az/instanceId
		awsID = tokens[1]
	}

	// We sanity check the resulting volume; the two known formats are
	// i-12345678 and i-12345678abcdef01
	if awsID == "" || !awsInstanceRegMatch.MatchString(awsID) {
		return "", fmt.Errorf("Invalid format for AWS instance (%s)", providerID)
	}

	return awsID, nil
}

// NewAWSProvider initializes a new AWS EC2 based Provider.
func NewAWSProvider(awsConfig AWSConfig, kubeClient kubernetes.Interface) (*AWSProvider, error) {
	config := aws.NewConfig()

	config.WithHTTPClient(
		instrumented_http.NewClient(config.HTTPClient, &instrumented_http.Callbacks{
			PathProcessor: func(path string) string {
				parts := strings.Split(path, "/")
				return parts[len(parts)-1]
			},
		}),
	)

	session, err := session.NewSessionWithOptions(session.Options{
		Config:            *config,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	if awsConfig.AssumeRole != "" {
		log.Infof("Assuming role: %s", awsConfig.AssumeRole)
		session.Config.WithCredentials(stscreds.NewCredentials(session, awsConfig.AssumeRole))
	}

	provider := &AWSProvider{
		client:     ec2.New(session),
		kubeClient: kubeClient,
		dryRun:     awsConfig.DryRun,
	}

	return provider, nil
}

func (p *AWSProvider) GetClusterName() (string, error) {
	if len(p.clusterName) == 0 {
		_, err := p.getInstances()
		if err != nil {
			return "", err
		}
	}
	return p.clusterName, nil
}

func (p *AWSProvider) Rules() ([]*inbound.InboundRules, error) {
	instances, err := p.getInstances()
	if err != nil {
		return nil, err
	}

	describeRequest := &ec2.DescribeSecurityGroupsInput{}
	filters := []*ec2.Filter{
		newEc2Filter("tag:"+TagNameExternalIPsPrefix+p.clusterName, ResourceLifecycleOwned),
	}
	describeRequest.Filters = filters
	response, err := p.DescribeSecurityGroups(describeRequest)
	if err != nil {
		return nil, err
	}

	result := []*inbound.InboundRules{}
	for _, sg := range response {
		rules := inbound.NewInboundRules()
		rules.Name = aws.StringValue(sg.GroupName)
		for i := range sg.IpPermissions {
			rule := inbound.InboundRule{
				Protocol: aws.StringValue(sg.IpPermissions[i].IpProtocol),
				Port:     int(aws.Int64Value(sg.IpPermissions[i].ToPort)),
			}
			rules.Rules = append(rules.Rules, rule)
			for _, instance := range instances {
				for _, isg := range instance.SecurityGroups {
					if aws.StringValue(isg.GroupId) == aws.StringValue(sg.GroupId) {
						providerID, ok := p.mapInstanceIdToProviderId[aws.StringValue(instance.InstanceId)]
						if !ok {
							return nil, fmt.Errorf("no ProviderID correspond to %s", aws.StringValue(instance.InstanceId))
						}
						rules.ProviderIDs = append(rules.ProviderIDs, providerID)
					}
				}
			}
		}
		result = append(result, rules)
	}
	return result, nil
}

func (p *AWSProvider) ApplyChanges(changes *plan.Changes) error {

	err := p.createSecurityGroups(changes)
	if err != nil {
		return err
	}

	err = p.updateSecurityGroups(changes)
	if err != nil {
		return err
	}

	err = p.setSecurityGroups(changes)
	if err != nil {
		return err
	}

	err = p.unsetSecurityGroups(changes)
	if err != nil {
		return err
	}

	err = p.deleteSecurityGroups(changes)
	if err != nil {
		return err
	}

	return nil
}

func (p *AWSProvider) getInstances() ([]*ec2.Instance, error) {
	nodes, err := p.kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	instanceIds := make([]*string, 0, len(nodes.Items))
	p.mapInstanceIdToProviderId = make(map[string]string, len(nodes.Items))
	for _, node := range nodes.Items {
		instanceId, err := mapToAWSInstanceID(node.Spec.ProviderID)
		if err != nil {
			return nil, err
		}
		instanceIds = append(instanceIds, aws.String(instanceId))
		p.mapInstanceIdToProviderId[instanceId] = node.Spec.ProviderID
	}

	request := &ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	}
	instances, err := p.DescribeInstances(request)
	if err != nil {
		return nil, err
	}

	if len(instances) > 0 {
		instance := instances[0]
		for _, tag := range instance.Tags {
			if aws.StringValue(tag.Key) == "KubernetesCluster" {
				p.clusterName = aws.StringValue(tag.Value)
				break
			}
		}
		p.vpcID = aws.StringValue(instance.VpcId)
	} else {
		return nil, fmt.Errorf("No instance was found")
	}

	return instances, nil
}

func (p *AWSProvider) findSecurityGroup(name string) (*ec2.SecurityGroup, error) {
	request := &ec2.DescribeSecurityGroupsInput{}
	filters := []*ec2.Filter{
		newEc2Filter("group-name", name),
		newEc2Filter("vpc-id", p.vpcID),
	}
	request.Filters = filters

	securityGroups, err := p.client.DescribeSecurityGroups(request)
	if err != nil {
		return nil, err
	}
	if len(securityGroups.SecurityGroups) > 1 || len(securityGroups.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group name is not unique %s", name)
	}
	sg := securityGroups.SecurityGroups[0]
	return sg, nil
}

func (p *AWSProvider) addInboundRules(groupId *string, rules []inbound.InboundRule) error {
	authorizeRequest := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: groupId,
	}

	for _, rule := range rules {
		perm := ec2.IpPermission{
			FromPort:   aws.Int64(int64(rule.Port)),
			IpProtocol: aws.String(rule.Protocol),
			IpRanges: []*ec2.IpRange{
				{
					CidrIp:      aws.String("0.0.0.0/0"),
					Description: aws.String(""),
				},
			},
			ToPort: aws.Int64(int64(rule.Port)),
		}
		authorizeRequest.IpPermissions = append(authorizeRequest.IpPermissions, &perm)
	}

	_, err := p.client.AuthorizeSecurityGroupIngress(authorizeRequest)
	if err != nil {
		return err
	}
	return nil
}

func (p *AWSProvider) createSecurityGroups(changes *plan.Changes) error {
	description := "Security group for External IPs"
	resources := make([]*string, 0, len(changes.Create))
	for _, r := range changes.Create {
		log.Infof("Desired change: %s %s", "CREATE SG", r)
		if !p.dryRun {
			request := &ec2.CreateSecurityGroupInput{}
			request.VpcId = &p.vpcID
			request.GroupName = &r.Name
			request.Description = &description

			response, err := p.client.CreateSecurityGroup(request)
			if err != nil {
				return err
			}

			resources = append(resources, response.GroupId)

			err = p.addInboundRules(response.GroupId, r.Rules)
			if err != nil {
				return err
			}
		}
	}

	if len(resources) > 0 {
		if !p.dryRun {
			input := &ec2.CreateTagsInput{
				Resources: resources,
				Tags: []*ec2.Tag{
					{
						Key:   aws.String(TagNameExternalIPsPrefix + p.clusterName),
						Value: aws.String(ResourceLifecycleOwned),
					},
				},
			}

			_, err := p.client.CreateTags(input)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AWSProvider) updateSecurityGroups(changes *plan.Changes) error {
	for _, r := range changes.UpdateNew {
		sg, err := p.findSecurityGroup(r.Name)
		if err != nil {
			return err
		}

		log.Infof("Desired change: %s %s", "UPDATE SG", r)
		if !p.dryRun {
			revokeRequest := &ec2.RevokeSecurityGroupIngressInput{}
			revokeRequest.GroupId = sg.GroupId
			revokeRequest.IpPermissions = sg.IpPermissions
			_, err = p.client.RevokeSecurityGroupIngress(revokeRequest)
			if err != nil {
				return err
			}

			err = p.addInboundRules(sg.GroupId, r.Rules)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *AWSProvider) deleteSecurityGroups(changes *plan.Changes) error {
	for _, r := range changes.Delete {
		sg, err := p.findSecurityGroup(r.Name)
		if err != nil {
			return err
		}

		log.Infof("Desired change: %s %s", "DELETE SG", r)
		if !p.dryRun {
			input := &ec2.DeleteSecurityGroupInput{
				GroupId: sg.GroupId,
			}

			_, err = p.client.DeleteSecurityGroup(input)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *AWSProvider) setSecurityGroups(changes *plan.Changes) error {
	for _, r := range changes.Set {
		instanceID, err := mapToAWSInstanceID(r.ProviderID)
		if err != nil {
			return err
		}
		input := &ec2.DescribeInstanceAttributeInput{
			Attribute:  aws.String("groupSet"),
			InstanceId: aws.String(instanceID),
		}

		result, err := p.client.DescribeInstanceAttribute(input)
		if err != nil {
			return err
		}

		sgs := result.Groups
		groups := make([]*string, 0, len(sgs)+1)
		found := false

		log.Infof("Desired change: %s %s %s", "ASSIGN SG", instanceID, r.RulesName)
		if !p.dryRun {
			sg, err := p.findSecurityGroup(r.RulesName)
			if err != nil {
				return err
			}

			for _, csg := range sgs {
				if aws.StringValue(csg.GroupId) == aws.StringValue(sg.GroupId) {
					found = true
				}
				groups = append(groups, csg.GroupId)
			}
			if !found {
				groups = append(groups, sg.GroupId)
			}

			input := &ec2.ModifyInstanceAttributeInput{
				InstanceId: aws.String(instanceID),
				Groups:     groups,
			}
			_, err = p.client.ModifyInstanceAttribute(input)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *AWSProvider) unsetSecurityGroups(changes *plan.Changes) error {
	for _, r := range changes.Unset {
		instanceID, err := mapToAWSInstanceID(r.ProviderID)
		if err != nil {
			return err
		}
		input := &ec2.DescribeInstanceAttributeInput{
			Attribute:  aws.String("groupSet"),
			InstanceId: aws.String(instanceID),
		}

		result, err := p.client.DescribeInstanceAttribute(input)
		if err != nil {
			return err
		}

		sgs := result.Groups
		groups := make([]*string, 0, len(sgs)+1)

		log.Infof("Desired change: %s %s %s", "UNASSIGN SG", instanceID, r.RulesName)
		if !p.dryRun {
			sg, err := p.findSecurityGroup(r.RulesName)
			if err != nil {
				return err
			}

			for _, csg := range sgs {
				if aws.StringValue(csg.GroupId) == aws.StringValue(sg.GroupId) {
					continue
				}
				groups = append(groups, csg.GroupId)
			}

			input := &ec2.ModifyInstanceAttributeInput{
				InstanceId: aws.String(instanceID),
				Groups:     groups,
			}
			_, err = p.client.ModifyInstanceAttribute(input)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, aws.String(value))
	}
	return filter
}

// Implementation of EC2.Instances
func (p *AWSProvider) DescribeInstances(request *ec2.DescribeInstancesInput) ([]*ec2.Instance, error) {
	// Instances are paged
	results := []*ec2.Instance{}
	var nextToken *string
	for {
		response, err := p.client.DescribeInstances(request)
		if err != nil {
			return nil, err
		}

		for _, reservation := range response.Reservations {
			results = append(results, reservation.Instances...)
		}

		nextToken = response.NextToken
		if aws.StringValue(nextToken) == "" {
			break
		}
		request.NextToken = nextToken
	}
	return results, nil
}

// Implements EC2.DescribeSecurityGroups
func (p *AWSProvider) DescribeSecurityGroups(request *ec2.DescribeSecurityGroupsInput) ([]*ec2.SecurityGroup, error) {
	// Security groups are not paged
	response, err := p.client.DescribeSecurityGroups(request)
	if err != nil {
		return nil, err
	}
	return response.SecurityGroups, nil
}
