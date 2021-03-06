# encoding: UTF-8

control 'V-218774' do
  title "The amount of private memory an application pool uses for each IIS
10.0 website must be explicitly set."
  desc  "IIS application pools can be periodically recycled to avoid unstable
states possibly leading to application crashes, hangs, or memory leaks. By
default, application pool recycling is overlapped, which means the worker
process to be shut down is kept running until after a new worker process is
started. After a new worker process starts, new requests are passed to it. The
old worker process shuts down after it finishes processing its existing
requests, or after a configured time-out, whichever comes first. This way of
recycling ensures uninterrupted service to clients."
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

    Scroll down to the \"Recycling\" section and verify the value for \"Private
Memory Limit\" is set to a value other than \"0\".

    If the \"Private Memory Limit\" is set to a value of \"0\", this is a
finding.
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Click \"Application Pools\".

    Perform the following for each Application Pool:

    Highlight an Application Pool and click \"Advanced Settings\" in the
\"Action\" Pane.

    Scroll down to the \"Recycling\" section and set the value for \"Private
Memory Limit\" to a value other than \"0\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-218774'
  tag rid: 'SV-218774r558649_rule'
  tag stig_id: 'IIST-SI-000254'
  tag fix_id: 'F-20245r311221_fix'
  tag cci: ['SV-109373', 'V-100269', 'CCI-000366']
  tag nist: ['CM-6 b']

  application_pool_names = json(command: 'ConvertTo-Json @(Get-ChildItem -Path IIS:\AppPools | select -expand name)').params

  application_pool_names.each do |application_pool|
    iis_configuration = json(command: "Get-ItemProperty 'IIS:\\AppPools\\#{application_pool}' -name * | select -expand recycling | select -expand periodicRestart | ConvertTo-Json")

    describe "The amount of private memory for IIS Application Pool :'#{application_pool}'" do
      subject { iis_configuration }
      its('privateMemory') { should_not cmp 0 }
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

