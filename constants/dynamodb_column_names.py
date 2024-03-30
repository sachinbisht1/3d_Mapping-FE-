"""Column names of dynamodb all tables."""
# UserProfile table
User_ID = "UserID"
Name_User = "NameUser"
Project_Permissions = "ProjectPermissions"
Company = "Company"
Email = "Email"
Contact_No = "ContactNo"
Secret_Key = "SecretKey"
Account_Created_At = "AccountCreatedAt"
Temp_Password = "TempPassword"
Temp_Password_Created_At = "TempPasswordCreatedAt"
Current_Project_Policy_Details = "CurrentProjectPolicyDetails"
Is_Super_Admin = "IsSuperAdmin"

# Project table
Project_ID = 'ProjectID'
Name_Project = 'ProjectName'
Project_Location = 'ProjectLocation'
S3_Directory = 'S3Directory'
History = 'History'
Category = 'Category'
Project_Users = 'ProjectUsers'
Project_Admins = 'ProjectAdmins'
Project_Status = 'ProjectStatus'
Project_Description = 'Description'
Latitude = 'Latitude'
Longitude = 'Longitude'
Created_At = 'CreationTimeStep'

# Policy table
Policy_ID = 'PolicyID'
Policy_Name = 'PolicyName'
Policy_Details = 'Details'

# Company table
Company_ID = 'CompanyID'
Company_Name = 'CompanyName'

# SuperAdmin table
Super_Admin_User_ID = 'SuperAdminUserID'
Super_Admin_Name = 'SuperAdminName'

# ProjectCategory table
Project_Category_ID = 'CategoryID'
Project_Category_Name = 'CategoryName'
