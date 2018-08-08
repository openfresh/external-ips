# ExternalIPs
ExternalIPs synchronizes exposed Kubernetes Services with DNS providers by using using ExternalIPs.

## What it Does

Inspired by [ExternalDNS](https://github.com/kubernetes-incubator/external-dns), ExternalIPs makes Kubernetes services discoverable via public DNS servers. Like External DNS, it retrieves a list of resources (Services, Node, etc.) from the [Kubernetes API](https://kubernetes.io/docs/api/) to determine a desired list of DNS records. *Unlike* ExternalDNS, however, it use [ExternalIPs](https://kubernetes.io/docs/concepts/services-networking/service/#external-ips) for exposing the service.

## Why using ExternalIPs

Kubernetes services can be exposed through a load balancer. However, there is no UDP load balancer on AWS at this moment. NodePort could be other option but the prot range is 30000-32767 by default. When you want to use smaller port number, it is not good option. [ExternalIPs](https://kubernetes.io/docs/concepts/services-networking/service/#external-ips) works perfectly in this scenario. It directly exposes service port without additional NodePort number.

## How it works

You annotate the services with your desired external DNS name. This program ExternalIPs finds the service with annotation. It picks up nodes to be accessed from public internet. It will configure firewall rule and DNS record with cloud provider API, and then update the services with ExternalIPs.

## Example

ExternalIPs will look for the annotation `external-ips.alpha.openfresh.github.io/hostname` on the service and use the corresponding value.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: udp-server
  annotations:
    external-ips.alpha.openfresh.github.io/hostname: udp-server.external-ips-test.my-org.com.
    external-ips.alpha.openfresh.github.io/selector: kops.k8s.io/instancegroup=general
    external-ips.alpha.openfresh.github.io/maxips: "2"
spec:
  type: LoadBalancer
  ports:
  - port: 6315
    protocol: UDP
    targetPort: 6315
  selector:
    app: udp-server
```

Optionaly, if you annotate `external-ips.alpha.openfresh.github.io/selector`, ExternalIPs will pick up only  the nodes with correspoinding value as a label. If you annotate `external-ips.alpha.openfresh.github.io/maxip`, you can limit the number of nodes to be exposed.

## IAM Permissions

```json
{
 "Version": "2012-10-17",
 "Statement": [
   {
     "Effect": "Allow",
     "Action": [
       "route53:ChangeResourceRecordSets"
     ],
     "Resource": [
       "arn:aws:route53:::hostedzone/*"
     ]
   },
   {
     "Effect": "Allow",
     "Action": [
       "route53:ListHostedZones",
       "route53:ListResourceRecordSets"
     ],
     "Resource": [
       "*"
     ]
   },
   {
     "Effect": "Allow",
     "Action": [
       "ec2:AuthorizeSecurityGroupIngress",
       "ec2:CreateSecurityGroup",
       "ec2:CreateTags",
       "ec2:DeleteSecurityGroup",
       "ec2:DescribeInstanceAttribute",
       "ec2:DescribeInstances",
       "ec2:DescribeSecurityGroups",
       "ec2:ModifyInstanceAttribute",
       "ec2:RevokeSecurityGroupIngress"
     ],
     "Resource": [
       "*"
     ]
   }
 ]
}
```

You need to make sure that your nodes (on which External DNS runs) have the IAM instance profile with the above IAM role assigned (either directly or via something like [kube2iam](https://github.com/jtblin/kube2iam)).