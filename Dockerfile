# Copyright (c) 2018 CyberAgent, Inc. All rights reserved.
# https://github.com/openfresh/external-ips

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# builder image
FROM golang as builder

WORKDIR /go/src/github.com/openfresh/external-ips
COPY . .
RUN make dep
RUN make test
RUN make build

# final image
FROM alpine:latest
MAINTAINER openfresh @ CyberAgent <valencia_dev@cyberagent.co.jp>

RUN apk add --no-cache ca-certificates
COPY --from=builder /go/src/github.com/openfresh/external-ips/build/external-ips /bin/external-ips

ENTRYPOINT ["/bin/external-ips"]