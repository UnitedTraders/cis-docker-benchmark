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

title 'Docker Daemon Configuration Files'

# attributes
REGISTRY_CERT_PATH = attribute('registry_cert_path')
REGISTRY_NAME = attribute('registry_name')
REGISTRY_CA_FILE = attribute('registry_ca_file')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'docker-3.1' do
  impact 1.0
  title 'Verify that docker.service file ownership is set to root:root'
  desc 'Verify that the \'docker.service\' file ownership and group-ownership are correctly set to \'root\'.

  Rationale: \'docker.service\' file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the file.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.1'
  tag 'cis-docker-1.13.0': '3.1'
  tag 'level:1'
  ref 'Control and configure Docker with systemd', url: 'https://docs.docker.com/engine/admin/systemd/'

  describe file(docker_helper.path) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'docker-3.2' do
  impact 1.0
  title 'Verify that docker.service file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'docker.service\' file permissions are correctly set to \'644\' or more restrictive.

  Rationale: \'docker.service\' file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should not be writable by any other user other than \'root\' to maintain the integrity of the file.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.2'
  tag 'cis-docker-1.13.0': '3.2'
  tag 'level:1'
  ref 'Control and configure Docker with systemd', url: 'https://docs.docker.com/engine/admin/systemd/'

  describe file(docker_helper.path) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'docker-3.3' do
  impact 1.0
  title 'Verify that docker.socket file ownership is set to root:root'
  desc 'Verify that the \'docker.socket\' file ownership and group-ownership are correctly set to \'root\'

  Rationale: \'docker.socket\' file contains sensitive parameters that may alter the behavior of Docker remote API. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the file.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.3'
  tag 'cis-docker-1.13.0': '3.3'
  tag 'level:1'
  ref 'Dockerd', url: 'https://docs.docker.com/engine/reference/commandline/dockerd/'
  ref 'YungSang/fedora-atomic-packer', url: 'https://github.com/YungSang/fedora-atomic-packer/blob/master/oem/docker.socket'
  ref 'CentOS 7/RHEL 7 and docker containers on boot', url: 'https://daviddaeschler.com/2014/12/14/centos-7rhel-7-and-docker-containers-on-boot/'

  describe file(docker_helper.socket) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'docker-3.4' do
  impact 1.0
  title 'Verify that docker.socket file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'docker.socket\' file permissions are correctly set to \'644\' or more restrictive.

  Rationale: \'docker.socket\' file contains sensitive parameters that may alter the behavior of Docker remote API. Hence, it should be writable only by \'root\' to maintain the integrity of the file.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.4'
  tag 'cis-docker-1.13.0': '3.4'
  tag 'level:1'
  ref 'Dockerd', url: 'https://docs.docker.com/engine/reference/commandline/dockerd/'
  ref 'YungSang/fedora-atomic-packer', url: 'https://github.com/YungSang/fedora-atomic-packer/blob/master/oem/docker.socket'
  ref 'CentOS 7/RHEL 7 and docker containers on boot', url: 'https://daviddaeschler.com/2014/12/14/centos-7rhel-7-and-docker-containers-on-boot/'

  describe file(docker_helper.socket) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'docker-3.5' do
  impact 1.0
  title 'Verify that /etc/docker directory ownership is set to root:root'
  desc '\'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the directory.

  Rationale: \'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the directory.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.5'
  tag 'cis-docker-1.13.0': '3.5'
  tag 'level:1'
  ref 'Protect the Docker daemon socket', url: 'https://docs.docker.com/engine/security/https/'

  describe file('/etc/docker') do
    it { should exist }
    it { should be_directory }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'docker-3.6' do
  impact 1.0
  title 'Verify that /etc/docker directory permissions are set to 755 or more restrictive'
  desc 'Verify that the /etc/docker directory permissions are correctly set to \'755\' or more restrictive.

  Rationale: \'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should only be writable by \'root\' to maintain the integrity of the directory.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.6'
  tag 'cis-docker-1.13.0': '3.6'
  tag 'level:1'
  ref 'Docker Security', url: 'https://docs.docker.com/engine/security/security/#conclusions'

  describe file('/etc/docker') do
    it { should exist }
    it { should be_directory }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_executable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should be_executable.by('other') }
  end
end

control 'docker-3.15' do
  impact 1.0
  title 'Verify that Docker socket file ownership is set to root:docker'
  desc 'Verify that the Docker socket file is owned by \'root\' and group-owned by \'docker\'.

  Rationale: Docker daemon runs as \'root\'. The default Unix socket hence must be owned by \'root\'. If any other user or process owns this socket, then it might be possible for that non-privileged user or process to interact with Docker daemon. Also, such a non-privileged user or process might interact with containers. This is neither secure nor desired behavior. Additionally, the Docker installer creates a Unix group called \'docker\'. You can add users to this group, and then those users would be able to read and write to default Docker Unix socket. The membership to the \'docker\' group is tightly controlled by the system administrator. If any other group owns this socket, then it might be possible for members of that group to interact with Docker daemon. Also, such a group might not be as tightly controlled as the \'docker\' group. This is neither secure nor desired behavior. Hence, the default Docker Unix socket file must be owned by \'root\' and group-owned by \'docker\' to maintain the integrity of the socket file.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.15'
  tag 'cis-docker-1.13.0': '3.15'
  tag 'level:1'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-socket-option'
  ref 'Protect the Docker daemon socket', url: 'https://docs.docker.com/engine/security/https/'

  describe file('/var/run/docker.sock') do
    it { should exist }
    it { should be_socket }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'docker' }
  end
end

control 'docker-3.16' do
  impact 1.0
  title 'Verify that Docker socket file permissions are set to 660 or more restrictive'
  desc 'Only \'root\' and members of \'docker\' group should be allowed to read and write to default Docker Unix socket. Hence, the Docket socket file must have permissions of \'660\' or more restrictive.

  Rationale: Only \'root\' and members of \'docker\' group should be allowed to read and write to default Docker Unix socket. Hence, the Docket socket file must have permissions of \'660\' or more restrictive.'

  tag 'docker'
  tag 'cis-docker-1.12.0': '3.16'
  tag 'cis-docker-1.13.0': '3.16'
  tag 'level:1'
  ref 'Use the Docker command line', url: 'https://docs.docker.com/engine/reference/commandline/cli/#daemon-socket-option'
  ref 'Protect the Docker daemon socket', url: 'https://docs.docker.com/engine/security/https/'

  describe file('/var/run/docker.sock') do
    it { should exist }
    it { should be_socket }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should_not be_executable.by('owner') }
    it { should be_readable.by('group') }
    it { should be_writable.by('group') }
    it { should_not be_executable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('other') }
  end
end
