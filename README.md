# microsoft-iis-10-site-stig-baseline  
InSpec profile to validate the secure configuration of Microsoft Internet Information Services (IIS) 10.0 Server, against [DISA](https://public.cyber.mil)'s Microsoft IIS 10.0 Site Security Technical Implementation Guide (STIG) Version 2, Release 1.

This Inspec Profile is in **draft** status.

## Running This Profile
The profile can be ran be using the below command.
```
inspec exec https://github.com/kclinden/microsoft-iis-10-site-stig-baseline -t winrm://$server --user $user --password $pass --reporter cli
```

## Info

Name: microsoft-iis-10-site-stig-baseline  
Author: Kasey Linden  
Status: accepted on 2020-09-25  
Copyright: N/A  
Copyright Email: N/A
Version: 2  
Release: 1  
Benchmark Date: 23 Oct 2020  
Reference: https://public.cyber.mil  
Reference by: DISA  
