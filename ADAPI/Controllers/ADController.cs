using ADAPI.APIWorker.Service;
using ADAPI.Logging;
using ADAPI.Messaging;
using ADAPI.Models.ActiveDirectory;
using ADAPI.Models.Wrapper;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace ADAPI.Controllers
{
    [System.Web.Mvc.RequireHttps]
    [System.Web.Http.RoutePrefix("api/SMGAD")]
    [System.Web.Mvc.Authorize]
    public class ADController : ApiController
    {
        private readonly IADService _adService;
        private readonly ILogger _logger;

        public ADController(IADService adService, ILogger logger)
        {
            _adService = adService;
            _logger = logger;
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("GetListSecurityGroups")]
        public ObservableCollection<ADObjectCheckList> GetAllSecurityGroups(WrapperModel wrapper)
        {
            try
            {
                ObservableCollection<ADObjectCheckList> results = _adService.GetAllSecurityGroups(wrapper);
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.APICallError, ex.StackTrace, ex.Message));
                return null;
            }
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllSecurityGroups")]
        public ObservableCollection<ADObjectCheckList> GetAllSecurityGroups()
        {
            try
            {
                ObservableCollection<ADObjectCheckList> results = _adService.GetAllSecurityGroups();
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.APICallError, ex.StackTrace, ex.Message));
                return null;
            }
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetSingleSecurityGroup")]
        public ObservableCollection<ADObjectCheckList> GetSpecificSecurityGroups(string securityGroup, string filter)
        {
            try
            {
                ObservableCollection<ADObjectCheckList> results = _adService.GetSpecificSecurityGroups(securityGroup, filter);
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.APICallError, ex.StackTrace, ex.Message));
                return null;
            }
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllDistroGroups")]
        public Collection<PSObject> GetAllDistroGroups()
        {
            try
            {
                Collection<PSObject> results = _adService.GetAllDistributionGroups();
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.APICallError, ex.StackTrace, ex.Message));
                return null;
            }
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetSingleDistroGroup")]
        public Collection<PSObject> GetIndividualDistroGroup(string name)
        {
            try
            {
                Collection<PSObject> results = _adService.GetIndividualDistributionGroups(name);
                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.APICallError, ex.StackTrace, ex.Message));
                return null;
            }
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetSamAccountUserName")]
        public async Task<string> GetSamAccountUserName(string userName)
        {
            return await _adService.GetSamAccountUserName(userName.Trim());
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("IsUserInGroup")]
        public async Task<bool> IsUserInAdGroup(string userName, string securityGroup)
        {
            return await _adService.IsUserInAdGroup(userName, securityGroup);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("DoesUserNameExist")]
        public async Task<bool> DoesUserNameExist(string userName)
        {
            return await _adService.DoesUserNameExist(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("IsAccountLocked")]
        public async Task<bool> IsAccountLocked(string userName)
        {
            return await _adService.IsAccountLocked(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("UnlockAccount")]
        public void UnlockAccount(string userName)
        {
            _adService.UnlockAccount(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("LockAccount")]
        public void LockAccount(string userName)
        {
            _adService.LockAccount(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("CreateNasFolder")]
        public bool CreateNASFolder(string userName)
        {
            return _adService.CreateNASFolder(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("MapUserDriveLetter")]
        public bool MapHomeFolder(string user, string driveLetter)
        {
            return _adService.MapHomeFolder(user, driveLetter);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("MapUserDriveLetterv2")]
        public bool MapHomeFolder(WrapperModel wrapper, string driveLetter)
        {
            return _adService.MapHomeFolder(wrapper, driveLetter);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetDisplayName")]
        public User GetADUserByDisplayName(string displayName)
        {
            return _adService.GetADUserByDisplayName(displayName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("SearchByLastName")]
        public async Task<List<ADPrincipalObject>> SearchADByLastName(string surname)
        {
            return await _adService.SearchADByLastName(surname);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllADUsers")]
        public async Task<List<ADPrincipalObject>> GetAllUsers()
        {
            return await _adService.GetAllUsers();
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("SearchADByName")]
        public async Task<ADPrincipalObject> SearchADByName(string userName)
        {
            return await _adService.SearchADByName(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllUserOUs")]
        public async Task<List<string>> GetUserOUs()
        {
            return await _adService.GetUserOUs();
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllUserOUsv2")]
        public async Task<List<string>> GetUserOUs(string filter)
        {
            return await _adService.GetUserOUs(filter);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("MoveOUs")]
        public void MoveUserToNewOU(string oldOU, string newOU)
        {
            _adService.MoveUserToNewOU(oldOU, newOU);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("MoveOUsv2")]
        public void MoveUserToNewOU(WrapperModel wrapper, string newOU)
        {
            _adService.MoveUserToNewOU(wrapper, newOU);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("IsUsernameAvailable")]
        public async Task<bool> CheckUserNameAvailability(string userName)
        {
            return await _adService.CheckUserNameAvailability(userName);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetSecurityGroups")]
        public Collection<PSObject> GetSecurityGroups()
        {
            return _adService.GetSecurityGroups();
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetSites")]
        public Collection<PSObject> GetADSites()
        {
            return _adService.GetADSites();
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("LDAPAuthentication")]
        public bool LDAPAuthentication(string userName, string password)
        {
            return _adService.LDAPAuthentication(userName, password);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("ChangeUserPassword")]
        public bool ChangeUserPassword(string samAccountName, string password)
        {
            return _adService.ChangeUserPassword(samAccountName, password);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllComputers")]
        public string[] GetComputersFromActiveDirectory()
        {
            return _adService.GetComputersFromActiveDirectory();
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("GetAllComputersv2")]
        public string[] GetComputersFromActiveDirectory(string filter)
        {
            return _adService.GetComputersFromActiveDirectory(filter);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("DisableUserAndGroups")]
        public void DisableUserAndRemoveFromGroups(WrapperModel wrapper)
        {
            _adService.DisableUserAndRemoveFromGroups(wrapper);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("ReEnableExistingUser")]
        public void ReEnableExistingUser(WrapperModel wrapper)
        {
            _adService.ReEnableExistingUser(wrapper);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("DeleteExistingUser")]
        public void DeleteExistingUser(WrapperModel wrapper)
        {
            _adService.DeleteExistingUser(wrapper);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("RemoveUserFromGroups")]
        public void RemoveUserFromGroups(WrapperModel wrapper)
        {
            _adService.RemoveUserFromGroups(wrapper);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("ReplaceUsersCurrentGroups")]
        public void ReplaceUsersCurrentGroupWithNewGroup(WrapperModel wrapper)
        {
            _adService.ReplaceUsersCurrentGroupWithNewGroup(wrapper);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("UpdateJobDescription")]
        public void UpdateUserJobDescription(string userDistinguishedName, string jobDescription)
        {
            _adService.UpdateUserJobDescription(userDistinguishedName, jobDescription);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("UpdateSiteInfo")]
        public void UpdateUserSiteInfo(string userDistinguishedName, string phone, string office, string managerDistinguishedName)
        {
            _adService.UpdateUserSiteInfo(userDistinguishedName, phone, office, managerDistinguishedName);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("CreateUser")]
        public void CreateNewUser(WrapperModel wrapper)
        {
            _adService.CreateNewUser(wrapper);
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("AddUserToGroups")]
        public void AddUserToGroups(WrapperModel wrapper)
        {
            _adService.AddUserToGroups(wrapper);
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("MoveUserToDisabledOU")]
        public void MoveUsersToDisabledOU(string oldOU)
        {
            _adService.MoveUsersToDisabledOU(oldOU);
        }
    }
}