# encoding: utf-8
# frozen_string_literal: true

# Copyright 2016, Patrick Muench
# Copyright 2017, Christoph Hartmann
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
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'Host Configuration'

DOCKER_VERSION = '19.03'
MANAGEABLE_CONTAINER_NUMBER = 25

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

# Docker Host Security Configuration Tests

control 'host-1.1' do
  impact 1.0
  title 'Use the updated Linux Kernel'
  desc 'Docker in daemon mode has specific kernel requirements. A 3.10 Linux kernel is the minimum requirement for Docker.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.2'
  tag 'level:1'
  
  only_if { os.linux? }
  kernel_version = command('uname -r | grep -o \'^\w\.\w*\.\w*\'').stdout
  kernel_compare = Gem::Version.new('3.10') <= Gem::Version.new(kernel_version)
  describe kernel_compare do
    it { should eq true }
  end
end

control 'host-1.2' do
  impact 1.0
  title 'Keep Docker up to date'
  desc 'There are frequent releases for Docker software that address security vulnerabilities,product bugs and bring in new functionality. Keep a tab on these product updates and upgrade as frequently as when new security vulnerabilities are fixed or deemed correct for your organization.

  Rationale: By staying up to date on Docker updates, vulnerabilities in the Docker software can be mitigated. An educated attacker may exploit known vulnerabilities when attempting to attain access or elevate privileges. Not installing regular Docker updates may leave you ith running vulnerable Docker software. It might lead to elevation privileges, unauthorized access or other security breaches. Keep a track of new releases and update as necessary.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.5'
  tag 'cis-docker-1.13.0': '1.3'
  tag 'level:1'
  
  docker_server_version = command('docker version --format \'{{.Server.Version}}\'').stdout
  docker_client_version = command('docker version --format \'{{.Client.Version}}\'').stdout
  
  docker_version_compare = docker_server_version==docker_client_version
  docker_version_latest_compare = Gem::Version.new(DOCKER_VERSION) <= Gem::Version.new(docker_server_version)

  describe docker_version_compare do
      it { should eq docker_version_latest_compare }
  end
end

control 'host-1.3' do
  impact 1.0
  title 'Audit docker daemon'
  desc 'Audit all Docker daemon activities.

  Rationale: Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with \'root\' privileges. It is thus necessary to audit its activities and usage.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.7'
  tag 'cis-docker-1.13.0': '1.5'
  tag 'level:1'
  ref 'System auditing', url: 'https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/chap-system_auditing.html'

  only_if { os.linux? }
  describe service('auditbeat') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

# Docker Security Operations Tests

control 'host-1.4' do
  impact 1.0
  title 'Avoid image sprawl'
  desc 'Do not keep a large number of container images on the same host. Use only tagged images as appropriate.

  Rationale: Tagged images are useful to fall back from "latest" to a specific version of an image in production. Images with unused or old tags may contain vulnerabilities that might be exploited, if instantiated. Additionally, if you fail to remove unused images from the system and there are various such redundant and unused images, the host filesystem may become full and could lead to denial of service.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.4'
  tag 'cis-docker-1.13.0': '1.4'
  tag 'level:1'
  ref 'Clean up unused Docker Containers and Images', url: 'http://craiccomputing.blogspot.de/2014/09/clean-up-unused-docker-containers-and.html'
  ref 'Command to remove all unused images', url: 'https://forums.docker.com/t/command-to-remove-all-unused-images/20/8'
  ref 'docker rmi --unused', url: 'https://github.com/moby/moby/issues/9054'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/'
  ref 'Add support for referring to images by digest', url: 'https://github.com/moby/moby/pull/11109'

  instantiated_images = command('docker ps -qa | xargs docker inspect -f \'{{.Image}}\'').stdout.split
  all_images = command('docker images -q --no-trunc').stdout.split
  diff = all_images - instantiated_images

  describe diff do
    it { should be_empty }
  end
end

control 'host-1.5' do
  impact 1.0
  title 'Avoid container sprawl'
  desc 'Do not keep a large number of containers on the same host.

  Rationale: The flexibility of containers makes it easy to run multiple instances of applications and indirectly leads to Docker images that exist at varying security patch levels. It also means that you are consuming host resources that otherwise could have been used for running \'useful\' containers. Having more than just the manageable number of containers on a particular host makes the situation vulnerable to mishandling, misconfiguration and fragmentation. Thus, avoid container sprawl and keep the number of containers on a host to a manageable total.'

  tag 'host'
  tag 'cis-docker-1.12.0': '1.5'
  tag 'cis-docker-1.13.0': '1.5'
  tag 'level:1'
  ref 'Security Risks and Benefits of Docker Application Containers', url: 'https://zeltser.com/security-risks-and-benefits-of-docker-application/'
  ref 'Docker networking: How Linux containers will change your network', url: 'http://searchsdn.techtarget.com/feature/Docker-networking-How-Linux-containers-will-change-your-network'

  total_on_host = command('docker info').stdout.split[1].to_i
  total_running = command('docker ps -q').stdout.split.length
  diff = total_on_host - total_running

  describe diff do
    it { should be <= MANAGEABLE_CONTAINER_NUMBER }
  end
end
