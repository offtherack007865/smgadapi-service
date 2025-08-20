using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ADAPI.Messaging
{
    public class ErrorMessages
    {
        public static readonly string AuthenticationError = @"Cannot authenticate to API Endpoint, or recieved bad data. See errors. Stacktrace: {0}. \r\n Message: {1}";
        public static readonly string APICallError = @"Cannot connect properly to API call. See errors. Stacktrace: {0} \r\n Message: {1}";
        public static readonly string GetAllSecurityGroupsError = @"GetAllSecurityGroups method failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string DoesUserNameExistError = @"DoesUserNameExist method has failed, see error: {0} Stacktrace: {1}.";
        public static readonly string IsAccountLockedError = @"IsAccountLocked method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string UnlockAccountError = @"UnlockAccount method has failed, see error: {0} Stacktrace: {1}.";
        public static readonly string MapHomeFolderError = @"MapHomeFolder method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string GetAdUserByDisplayError = @"GetAdUserByDisplay method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string SearchADByLastNameError = @"SearchADByLastName method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string GetAllUsersError = @"GetAllUsers method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string SearchADByNameError = @"SearchADByName method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string MoveUserToNewOUError = @"MoveUserToNewOU method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string CheckUserNameAvailabilityError = @"CheckUserNameAvailability method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string PowershellError = @"Cannot make Powershell call, see error: {0}. Stacktrace: {1}.";
        public static readonly string LDAPConnectionError = @"Trouble connecting to domain, see error: {0}, Stacktrace: {1}";
        public static readonly string DisableUserAndRemoveFromGroupsError = @"DisableUserAndRemoveFromGroups method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string ReEnableExistingUserError = @"ReEnableExistingUser method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string DeleteExistingUserError = @"DeleteExistingUser method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string RemoveUsersFromGroupError = @"RemoveUsersFromGroup method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string ReplaceUsersCurrentGroupError = @"ReplaceUsersCurrentGroup method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string UpdateUserJobDescriptionError = @"UpdateUserJobDescription method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string UpdateUserSiteInfoError = @"UpdateUserSiteInfo method has failed, see error: {0}. Stacktrace {1}.";
        public static readonly string AddUserToGroupsError = @"AddUserToGroups method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string GetUserOUsError = @"GetUserOUs method has failed, see error: {0}. Stacktrace: {1}.";
        public static readonly string CreateUserError = @"Cannot create user, see error: {0}. Stacktrace: {1}.";
        public static readonly string NASCreationError = @"Cannot write {0} to network location. See error: {1}. Stacktrace: {2}.";

    }
}