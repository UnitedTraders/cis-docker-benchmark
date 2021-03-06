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

title 'Docker Configuration Files'

DOCKER_SERVICE_PATH='/usr/lib/systemd/system/docker.service'

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

# Docker Daemon Security Configuration Tests

control 'docker-1.1' do
  impact 1.0
  title 'Verify that docker.service file ownership is set to root:root'
  desc 'Verify that the \'docker.service\' file ownership and group-ownership are correctly set to \'root\'.

  Rationale: \'docker.service\' file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the file.'

  describe file(DOCKER_SERVICE_PATH) do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'docker-1.2' do
  impact 1.0
  title 'Verify that docker.service file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'docker.service\' file permissions are correctly set to \'644\' or more restrictive.

  Rationale: \'docker.service\' file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should not be writable by any other user other than \'root\' to maintain the integrity of the file.'

  describe file(DOCKER_SERVICE_PATH) do
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

control 'docker-1.3' do
  impact 1.0
  title 'Verify that /etc/docker directory ownership is set to root:root'
  desc '\'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the directory.

  Rationale: \'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should be owned and group-owned by \'root\' to maintain the integrity of the directory.'

  describe file('/etc/docker') do
    it { should exist }
    it { should be_directory }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'docker-1.4' do
  impact 1.0
  title 'Verify that /etc/docker directory permissions are set to 755 or more restrictive'
  desc 'Verify that the /etc/docker directory permissions are correctly set to \'755\' or more restrictive.

  Rationale: \'/etc/docker\' directory contains certificates and keys in addition to various sensitive files. Hence, it should only be writable by \'root\' to maintain the integrity of the directory.'

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

control 'docker-1.5' do
  impact 1.0
  title 'Verify that Docker socket file ownership is set to root:docker'
  desc 'Verify that the Docker socket file is owned by \'root\' and group-owned by \'docker\'.

  Rationale: Docker daemon runs as \'root\'. The default Unix socket hence must be owned by \'root\'. If any other user or process owns this socket, then it might be possible for that non-privileged user or process to interact with Docker daemon. Also, such a non-privileged user or process might interact with containers. This is neither secure nor desired behavior. Additionally, the Docker installer creates a Unix group called \'docker\'. You can add users to this group, and then those users would be able to read and write to default Docker Unix socket. The membership to the \'docker\' group is tightly controlled by the system administrator. If any other group owns this socket, then it might be possible for members of that group to interact with Docker daemon. Also, such a group might not be as tightly controlled as the \'docker\' group. This is neither secure nor desired behavior. Hence, the default Docker Unix socket file must be owned by \'root\' and group-owned by \'docker\' to maintain the integrity of the socket file.'

  describe file('/var/run/docker.sock') do
    it { should exist }
    it { should be_socket }
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'docker' }
  end
end

control 'docker-1.6' do
  impact 1.0
  title 'Verify that Docker socket file permissions are set to 660 or more restrictive'
  desc 'Only \'root\' and members of \'docker\' group should be allowed to read and write to default Docker Unix socket. Hence, the Docket socket file must have permissions of \'660\' or more restrictive.

  Rationale: Only \'root\' and members of \'docker\' group should be allowed to read and write to default Docker Unix socket. Hence, the Docket socket file must have permissions of \'660\' or more restrictive.'

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

