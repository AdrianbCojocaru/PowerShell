# SCCM Collection clean-up
Removes SCCM Collections even if they are part of the Include/Exclude Collection Rules.  
![Include Collection Rule](https://github.com/AdrianbCojocaru/PowerShell/blob/master/SCCM/CollectionCleanUp/pic/CollectionRule.jpg)  


### Description

Place the collections names that you want removed in <ScriptPath>\Data\CollectionNamesToBeCleaned.txt - each name on a new line  
  The script will first look for and remove the relationships for each collection from the SQL DB. Then it will delete the collection itself.  

  -Confirm switch will require you to confirm the removal if:  
    - the collection is not empty  
    - the collection has 5 or more relationships  
Based on https://jordantheitguy.com/2017/10/01/sccm-collection-relationships/
