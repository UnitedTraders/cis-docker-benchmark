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

title 'Container Runtime'

# attributes
CONTAINER_CAPADD = attribute('container_capadd')
SELINUX_PROFILE = attribute('selinux_profile')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'docker-5.6' do
  impact 1.0
  title 'Do not run ssh within containers'
  desc 'SSH server should not be running within the container. You should SSH into the Docker host, and use nsenter tool to enter a container from a remote host.

  Rationale: Running SSH within the container increases the complexity of security management by making it

            Difficult to manage access policies and security compliance for SSH server
            Difficult to manage keys and passwords across various containers
            Difficult to manage security upgrades for SSH server

  It is possible to have shell access to a container without using SSH, the needlessly increasing the complexity of security management should be avoided.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.6'
  tag 'cis-docker-1.13.0': '5.6'
  tag 'level:1'
  ref 'Why you don\'t need to run SSHd in your Docker containers', url: 'https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/'

  docker.containers.running?.ids.each do |id|
    execute_command = 'docker exec ' + id + ' ps -e'
    describe command(execute_command) do
      its('stdout') { should_not match(/ssh/) }
    end
  end
end

control 'docker-5.7' do
  impact 1.0
  title 'Do not map privileged ports within containers'
  desc 'The TCP/IP port numbers below 1024 are considered privileged ports. Normal users and processes are not allowed to use them for various security reasons. Docker allows a container port to be mapped to a privileged port.

  Rationale: By default, if the user does not specifically declare the container port to host port mapping, Docker automatically and correctly maps the container port to one available in 49153-65535 block on the host. But, Docker allows a container port to be mapped to a privileged port on the host if the user explicitly declared it. This is so because containers are executed with NET_BIND_SERVICE Linux kernel capability that does not restrict the privileged port mapping. The privileged ports receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.7'
  tag 'cis-docker-1.13.0': '5.7'
  tag 'level:1'
  ref 'Bind container ports to the host', url: 'https://docs.docker.com/engine/userguide/networking/default_network/binding/'
  ref 'Why putting SSH on another port than 22 is bad idea', url: 'https://www.adayinthelifeof.nl/2012/03/12/why-putting-ssh-on-another-port-than-22-is-bad-idea/'

  docker.containers.running?.ids.each do |id|
    container_info = docker.object(id)
    next if container_info['NetworkSettings']['Ports'].nil?
    container_info['NetworkSettings']['Ports'].each do |_, hosts|
      next if hosts.nil?
      hosts.each do |host|
        describe host['HostPort'].to_i.between?(1, 1024) do
          it { should eq false }
        end
      end
    end
  end
end

control 'docker-5.19' do
  impact 1.0
  title 'Do not set mount propagation mode to shared'
  desc 'Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode until needed.

  Rationale: A shared mount is replicated at all mounts and the changes made at any mount point are propagated to all mounts. Mounting a volume in shared mode does not restrict any other container to mount and make changes to that volume. This might be catastrophic if the mounted volume is sensitive to changes. Do not set mount propagation mode to shared until needed.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.19'
  tag 'cis-docker-1.13.0': '5.19'
  tag 'level:1'
  ref 'Capability to specify per volume mount propagation mode', url: 'https://github.com/docker/docker/pull/17034'
  ref 'Docker run reference', url: 'https://docs.docker.com/engine/reference/run/'
  ref 'Shared Subtrees', url: 'https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt'

  docker.containers.running?.ids.each do |id|
    raw = command("docker inspect --format '{{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}' #{id}").stdout
    describe raw.delete("\n").delete('\"').delete(' ') do
      it { should_not eq 'shared' }
    end
  end
end

control 'docker-5.22' do
  impact 1.0
  title 'Do not docker exec commands with privileged option'
  desc 'Do not docker exec with --privileged option.

  Rationale: Using --privileged option in docker exec gives extended Linux capabilities to the command. This could potentially be insecure and unsafe to do especially when you are running containers with dropped capabilities or with enhanced restrictions.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.22'
  tag 'cis-docker-1.13.0': '5.22'
  tag 'level:2'
  ref 'docker exec', url: 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep privileged').stdout do
    it { should be_empty }
  end
end

control 'docker-5.23' do
  impact 1.0
  title 'Do not docker exec commands with user option'
  desc 'Do not docker exec with --user option.

  Rationale: Using --user option in docker exec executes the command within the container as that user. This could potentially be insecure and unsafe to do especially when you are running containers with dropped capabilities or with enhanced restrictions. For example, suppose your container is running as tomcat user (or any other non-root user), it would be possible to run a command through docker exec as root with --user=root option. This could potentially be dangerous.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '5.23'
  tag 'cis-docker-1.13.0': '5.23'
  tag 'level:2'
  ref 'docker exec', url: 'https://docs.docker.com/engine/reference/commandline/exec/'

  describe command('ausearch --input-logs -k docker | grep exec | grep user').stdout do
    it { should be_empty }
  end
end
