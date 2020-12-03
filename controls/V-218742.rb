# encoding: UTF-8

control 'V-218742' do
  title "The IIS 10.0 website must produce log records containing sufficient
information to establish the identity of any user/subject or process associated
with an event."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Determining user accounts, processes running on behalf of the user, and
running process identifiers also enable a better understanding of the overall
event. User tool identification is also helpful to determine if events are
related to overall user access or specific client tools.

    Log record content that may be necessary to satisfy the requirement of this
control includes: time stamps, source and destination addresses, user/process
identifiers, event descriptions, success/fail indications, file names involved,
and access control or flow control rules invoked.
  "
  desc  'rationale', ''
  desc  'check', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Access the IIS 10.0 web server IIS 10.0 Manager.

    Under \"IIS\", double-click the \"Logging\" icon.

    Verify the \"Format:\" under \"Log File\" is configured to \"W3C\".

    Select \"Fields\".

    Under \"Standard Fields\", verify \"User Agent\", \"User Name\", and
\"Referrer\" are selected.

    Under \"Custom Fields\", verify the following fields have been configured:

    Request Header >> Authorization

    Response Header >> Content-Type

    If any of the above fields are not selected, this is a finding.
  "
  desc  'fix', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Access the IIS 10.0 web server IIS 10.0 Manager.

    Select the website being reviewed.

    Under \"IIS\", double-click the \"Logging\" icon.

    Configure the \"Format:\" under \"Log File\" to \"W3C\".

    Select \"Fields\".

    Under \"Standard Fields\", select \"User Agent\", \"User Name\", and
\"Referrer\".

    Under \"Custom Fields\", select the following fields:

    Request Header >> Authorization

    Response Header >> Content-Type

    Click \"OK\".

    Select \"Apply\" from the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000100-WSR-000064'
  tag gid: 'V-218742'
  tag rid: 'SV-218742r558649_rule'
  tag stig_id: 'IIST-SI-000210'
  tag fix_id: 'F-20213r311125_fix'
  tag cci: ['SV-109309', 'V-100205', 'CCI-001487']
  tag nist: ['AU-3']
end

