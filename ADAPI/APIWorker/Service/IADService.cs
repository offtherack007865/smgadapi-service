using ADAPI.Models.ActiveDirectory;
using ADAPI.Models.Wrapper;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace ADAPI.APIWorker.Service
{
    public interface IADService
    {
        ObservableCollection<ADObjectCheckList> GetAllSecurityGroups(WrapperModel wrapper);
        ObservableCollection<ADObjectCheckList> GetAllSecurityGroups();
        ObservableCollection<ADObjectCheckList> GetSpecificSecurityGroups(string securityGroup, string filter);
        Collection<PSObject> GetAllDistributionGroups();
        Collection<PSObject> GetIndividualDistributionGroups(string name);
        Task<string> GetSamAccountUserName(string userName);
        Task<bool> IsUserInAdGroup(string userName, string securityGroup);
        Task<bool> DoesUserNameExist(string userName);
        Task<bool> IsAccountLocked(string userName);
        void UnlockAccount(string userName);
        void LockAccount(string userName);
        bool CreateNASFolder(string userName);
        bool MapHomeFolder(string user, string driveLetter);
        bool MapHomeFolder(WrapperModel wrapper, string driveLetter);
        User GetADUserByDisplayName(string displayName);
        Task<List<ADPrincipalObject>> SearchADByLastName(string surname);
        Task<List<ADPrincipalObject>> GetAllUsers();
        Task<ADPrincipalObject> SearchADByName(string name);
        Task<List<string>> GetUserOUs();
        Task<List<string>> GetUserOUs(string filter);
        void MoveUserToNewOU(string oldOU, string newOU);
        void MoveUserToNewOU(WrapperModel wrapper, string newOU);
        Task<bool> CheckUserNameAvailability(string userName);
        Collection<PSObject> GetSecurityGroups();
        Collection<PSObject> GetADSites();
        bool LDAPAuthentication(string userName, string password);
        bool ChangeUserPassword(string samAccountName, string password);
        string[] GetComputersFromActiveDirectory();
        string[] GetComputersFromActiveDirectory(string filter);
        void DisableUserAndRemoveFromGroups(WrapperModel wrapper);
        void ReEnableExistingUser(WrapperModel wrapper);
        void DeleteExistingUser(WrapperModel wrapper);
        void RemoveUserFromGroups(WrapperModel wrapper);
        void ReplaceUsersCurrentGroupWithNewGroup(WrapperModel wrapper);
        void UpdateUserJobDescription(string userDistinguishedName, string jobDescription);
        void UpdateUserSiteInfo(string userDistinguishedName, string phone, string office, string managerDistinguishedName);
        void CreateNewUser(WrapperModel wrapper);
        void AddUserToGroups(WrapperModel wrapper);
        void MoveUsersToDisabledOU(string oldOU);
    }
}