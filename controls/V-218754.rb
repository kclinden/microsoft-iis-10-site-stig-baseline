# encoding: UTF-8

control 'V-218754' do
  title "The IIS 10.0 website must be configured to limit the size of web
requests."
  desc  "By setting limits on web requests, it ensures availability of web
services and mitigates the risk of buffer overflow type attacks. The
maxAllowedContentLength Request Filter limits the number of bytes the server
will accept in a request."
  desc  'rationale', ''
  desc  'check', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Click on the site name.

    Double-click the \"Request Filtering\" icon.

    Click \"Edit Feature Settings\" in the \"Actions\" pane.

    If the \"maxAllowedContentLength\" value is not explicitly set to
\"30000000\" or less or a length documented and approved by the ISSO, this is a
finding.
  "
  desc  'fix', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Click the site name under review.

    Double-click the \"Request Filtering\" icon.

    Click \"Edit Feature Settings\" in the \"Actions\" pane.

    Set the \"maxAllowedContentLength\" value to \"30000000\" or less.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag gid: 'V-218754'
  tag rid: 'SV-218754r558649_rule'
  tag stig_id: 'IIST-SI-000226'
  tag fix_id: 'F-20225r311161_fix'
  tag cci: ['V-100229', 'SV-109333', 'CCI-001094']
  tag nist: ['SC-5 (1)']
end

