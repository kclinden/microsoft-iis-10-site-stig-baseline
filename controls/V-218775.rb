# encoding: UTF-8

control 'V-218775' do
  title "The application pool for each IIS 10.0 website must have a recycle
time explicitly set."
  desc  "Application pools can be periodically recycled to avoid unstable
states possibly leading to application crashes, hangs, or memory leaks."
  desc  'rationale', ''
  desc  'check', "
    Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is
Not Applicable.

    If this IIS 10.0 installation is supporting Microsoft Exchange, and not
otherwise hosting any content, this requirement is Not Applicable.

    Open the IIS 10.0 Manager.

    Perform the following for each Application Pool:

    Click \"Application Pools\".

    Highlight an Application Pool and click \"Advanced Settings\" in the
\"Action\" Pane.

    Scroll down to the \"Recycling\" section and expand the \"Generate Recycle
Event Log Entry\" section.

    Verify both the \"Regular time interval\" and \"Specific time\" options are
set to \"True\".

    If both the \"Regular time interval\" and \"Specific time\" options are not
set to \"True\", this is a finding.
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Click \"Application Pools\".

    Perform the following for each Application Pool:

    Highlight an Application Pool and click \"Advanced Settings\" in the
\"Action\" Pane.

    Scroll down to the \"Recycling\" section and expand the \"Generate Recycle
Event Log Entry\" section.

    Set both the \"Regular time interval\" and \"Specific time\" options to
\"True\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-218775'
  tag rid: 'SV-218775r558649_rule'
  tag stig_id: 'IIST-SI-000255'
  tag fix_id: 'F-20246r311224_fix'
  tag cci: ['V-100271', 'SV-109375', 'CCI-000366']
  tag nist: ['CM-6 b']

  application_pool_names = json(command: 'ConvertTo-Json @(Get-ChildItem -Path IIS:\AppPools | select -expand name)').params

  application_pool_names.each do |application_pool|
    iis_configuration = json(command: "Get-ItemProperty 'IIS:\\AppPools\\#{application_pool}' -name * | select -expand recycling | ConvertTo-Json")

    describe "The recycle time for IIS Application Pool :'#{application_pool}" do
      subject { iis_configuration }
      its('logEventOnRecycle') { should include 'Time' }
      its('logEventOnRecycle') { should include 'Schedule' }
    end
  end
  if application_pool_names.empty?
    impact 0.0
    desc 'There are no application pool configured hence the control is Not-Applicable'

    describe 'No application pool where found to be reviewed' do
      skip 'No application pool where found to be reviewed'
    end
  end

end

