# Description
Script for updating Device groups based on User groups.  
Built to run on a schedule inside an Azure runbook.  
  
Uses a JSON configuration file stored on blob storage that defines the source & target groups.  
When new groups are added, only this file will change.  

## Required Permissions
  *Microsoft Graph (3)*  
    Device.Read.All  
    GroupMember.ReadWrite.All  
    User.Read.All