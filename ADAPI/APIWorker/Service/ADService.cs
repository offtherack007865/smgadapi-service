using ADAPI.APIWorker.Impersonation;
using ADAPI.Logging;
using ADAPI.Messaging;
using ADAPI.Models.ActiveDirectory;
using ADAPI.Models.Config;
using ADAPI.Models.Wrapper;
using ADAPI.Utilities;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace ADAPI.APIWorker.Service
{
    public class ADService : IADService
    {
        private ILogger _logger;
        private APIConfiguration _impersonation;
        private APIConfiguration _networkInfo;

        public ADService(ILogger logger)
        {
            _logger = logger;

            _impersonation = Config.GetAuthenticationInfo("Impersonation");
            _networkInfo = Config.GetNetworkInfo("Directories");
        }

        /// <summary>
        /// Takes the security group OU from Active Directory, finds each one and then stores them in the observable collection list.
        /// </summary>
        /// <param name="organizations"></param>
        /// <returns></returns>
        public ObservableCollection<ADObjectCheckList> GetAllSecurityGroups(WrapperModel wrapper)
        {
            ObservableCollection<ADObjectCheckList> list = new ObservableCollection<ADObjectCheckList>();
            List<ADObjectCheckList> sortingList = new List<ADObjectCheckList>();

            try
            {
                using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                {
                    foreach (string organization in wrapper.OrganizationalGroups)
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain, organization))
                        {
                            using (GroupPrincipal groupPrincipal = new GroupPrincipal(principalContext))
                            {
                                using (PrincipalSearcher principalSearcher = new PrincipalSearcher(groupPrincipal))
                                {
                                    foreach (Principal found in principalSearcher.FindAll())
                                    {
                                        sortingList.Add(new ADObjectCheckList
                                        {
                                            Name = found.Name,
                                            DistinguishedName = found.DistinguishedName,
                                            Checked = false
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.GetAllSecurityGroupsError, ex.Message, ex.StackTrace));
            }

            foreach (ADObjectCheckList item in sortingList.OrderBy(x => x.Name))
            {
                list.Add(item);
            }

            return list;
        }

        /// <summary>
        /// Gets All Security Groups listed in Active Directory, finds them and stores them in an observable collection list.
        /// </summary>
        /// <returns></returns>
        public ObservableCollection<ADObjectCheckList> GetAllSecurityGroups()
        {
            ObservableCollection<ADObjectCheckList> list = new ObservableCollection<ADObjectCheckList>();
            List<ADObjectCheckList> sortingList = new List<ADObjectCheckList>();
            
            try
            {
                using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                {
                    using (GroupPrincipal groupPrincipal = new GroupPrincipal(principalContext))
                    {
                        groupPrincipal.IsSecurityGroup = true;
                        using (PrincipalSearcher principalSearcher = new PrincipalSearcher(groupPrincipal))
                        {
                            foreach (Principal found in principalSearcher.FindAll())
                            {
                                sortingList.Add(new ADObjectCheckList
                                {
                                    Name = found.Name,
                                    DistinguishedName = found.DistinguishedName,
                                    Checked = false
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.GetAllSecurityGroupsError, ex.Message, ex.StackTrace));
            }

            foreach (ADObjectCheckList item in sortingList.OrderBy(x => x.Name))
            {
                list.Add(item);
            }

            return list;
        }

        /// <summary>
        /// Uses powershell to get Security Groups to refresh list from Remote Offices SG.
        /// </summary>
        public ObservableCollection<ADObjectCheckList> GetSpecificSecurityGroups(string securityGroup, string filter)
        {
            ObservableCollection<ADObjectCheckList> list = new ObservableCollection<ADObjectCheckList>();
            List<ADObjectCheckList> sortingList = new List<ADObjectCheckList>();
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript(string.Format(@"import-module activedirectory; Get-ADGroup -SearchBase '{0}' -Filter {{Name -like '*{1}*'}};", securityGroup, filter));
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine(error.Exception.Message);
                            _logger.LogError(sb.ToString());
                        }
                    }
                    if (PSOutput.Count > 0)
                    {
                        foreach (PSObject securitygroup in PSOutput)
                        {
                            if (securitygroup.Properties["DistinguishedName"].Value.ToString() != null && securitygroup.Properties["Name"].Value.ToString() != null)
                            {
                                sortingList.Add(new ADObjectCheckList
                                {
                                    Name = securitygroup.Properties["Name"].Value.ToString(),
                                    DistinguishedName = securitygroup.Properties["DistinguishedName"].Value.ToString(),
                                    Checked = false
                                });
                            }
                        }
                    }
                }

                foreach (ADObjectCheckList item in sortingList.OrderBy(x => x.Name))
                {
                    list.Add(item);
                }

                return list;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.PowershellError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Gets all Distribution Groups listed in Active Directory, finds them and stores them in an observable collection list.
        /// </summary>
        /// <returns></returns>
        public Collection<PSObject> GetAllDistributionGroups()
        {
            Collection<PSObject> results = new Collection<PSObject>();
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    //I know i told it to grab more, just currently only need DN and name.
                    PowerShellInstance.AddScript(@"import-module activedirectory; Get-ADGroup -Filter ""groupcategory -eq 'Distribution'"" -prop managedby,mail;");
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine(error.Exception.Message);
                            _logger.LogError(sb.ToString());
                        }
                    }
                    if (PSOutput.Count > 0)
                    {
                        foreach (PSObject securitygroup in PSOutput)
                        {
                            if (securitygroup.Properties["DistinguishedName"].Value.ToString() != null && securitygroup.Properties["Name"].Value.ToString() != null)
                            {
                                results.Add(securitygroup);
                            }
                        }
                    }
                }

                return results;

            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.PowershellError, ex.Message, ex.StackTrace));
                throw;
            }

        }

        /// <summary>
        /// Searches all Distribution Groups listed in Active Directory, determines if the name matches, to return any that match.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public Collection<PSObject> GetIndividualDistributionGroups(string name)
        {
            Collection<PSObject> results = new Collection<PSObject>();
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript(@"import-module activedirectory; Get-ADGroup -Filter ""groupcategory -eq 'Distribution'"" -prop managedby,mail;");
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine(error.Exception.Message);
                            _logger.LogError(sb.ToString());
                        }
                    }
                    if (PSOutput.Count > 0)
                    {
                        foreach (PSObject distroGroup in PSOutput)
                        {
                            if (distroGroup.Properties["Name"].Value.ToString() != null && distroGroup.Properties["Name"].Value.ToString().Contains(name))
                            {
                                results.Add(distroGroup);
                            }
                        }
                    }
                }

                return results;

            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.PowershellError, ex.Message, ex.StackTrace));
                throw;
            }

        }

        /// <summary>
        /// Gets specific sam account name based on windows login.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public async Task<string> GetSamAccountUserName(string userName)
        {
            Task<string> samNameTask = Task.Run(() =>
            {
                using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain))
                {
                    UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, userName);

                    return user?.SamAccountName;
                }
            });
            await Task.WhenAll(samNameTask);
            return samNameTask.Result;
        }

        /// <summary>
        /// Searches specified security group for sam account.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public async Task<bool> IsUserInAdGroup(string userName, string securityGroup)
        {
            using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
            {
                Task<bool> adTask = Task.Run(async () =>
                {
                    string samAccountName = await GetSamAccountUserName(userName);
                    if (!string.IsNullOrEmpty(samAccountName))
                    {
                        GroupPrincipal groupPrincipal = GroupPrincipal.FindByIdentity(principalContext, securityGroup);
                        List<Principal> members = groupPrincipal?.GetMembers().Where(x => x.SamAccountName == samAccountName).ToList();
                        if (members?.Count > 0)
                        {
                            return true;
                        }
                    }
                    return false;
                });
                await Task.WhenAll(adTask);
                return adTask.Result;
            }
        }

        /// <summary>
        /// Searches AD using unique id to determine if user object exists. then bool conditioned applies depending on its results.
        /// </summary>
        /// <param name="username"></param>
        /// <returns>bool</returns>
        public async Task<bool> DoesUserNameExist(string username)
        {
            try
            {
                Task<bool> usernameTask = Task.Run(() =>
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal user = new UserPrincipal(principalContext))
                        {
                            user.SamAccountName = username;
                            using (PrincipalSearcher searcher = new PrincipalSearcher(user))
                            {
                                foreach (Principal found in searcher.FindAll())
                                {
                                    if (found.SamAccountName == username)
                                    {
                                        return true;

                                    }
                                }
                            }
                        }
                    }
                    return false;
                });
                await Task.WhenAll(usernameTask);
                return usernameTask.Result;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.DoesUserNameExistError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Uses AD to determine if Account is locked. Uses the SAM account name to determine the username.
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public async Task<bool> IsAccountLocked(string username)
        {
            try
            {
                Task<bool> accountlockedTask = Task.Run(() =>
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal user = new UserPrincipal(principalContext))
                        {
                            user.SamAccountName = username;
                            using (PrincipalSearcher searcher = new PrincipalSearcher(user))
                            {
                                foreach (UserPrincipal found in searcher.FindAll())
                                {
                                    if (found.SamAccountName == username)
                                    {
                                        if (found.IsAccountLockedOut())
                                        {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return false;
                });
                await Task.WhenAll(accountlockedTask);
                return accountlockedTask.Result;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.IsAccountLockedError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Unlocks AD Object.
        /// </summary>
        /// <param name="username"></param>
        public async void UnlockAccount(string username)
        {
            try
            {
                Task accountUnlockTask = Task.Run(() =>
                {
                    using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                        {
                            using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(principalContext, IdentityType.SamAccountName, username))
                            {
                                userPrincipal.UnlockAccount();
                                userPrincipal.Save();
                            }
                        }
                    }
                });
                await Task.WhenAll(accountUnlockTask);
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.UnlockAccountError, ex.Message, ex.StackTrace));
            }
        }

        /// <summary>
        /// Locks AD Object by purposely failing log-in attempts.
        /// </summary>
        /// <param name="username"></param>
        public async void LockAccount(string username)
        {
            try
            {
                Task accountLockTask = Task.Run(() =>
                {
                    using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Password))
                        {
                            using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(principalContext, IdentityType.SamAccountName, username))
                            {
                                using (DirectoryEntry directoryEntry = new DirectoryEntry(userPrincipal.DistinguishedName))
                                {
                                    string badPassword = "ThisPasswordIsToForceReset";
                                    int maxLoginAttempts = 10;

                                    for (int i = 0; i < maxLoginAttempts; i++)
                                    {
                                        try
                                        {
                                            new DirectoryEntry(directoryEntry.Path, userPrincipal.UserPrincipalName.Split('@').First(), badPassword).RefreshCache();
                                        }
                                        catch (Exception ex)
                                        {
                                            _logger.LogError(string.Format(ErrorMessages.IsAccountLockedError, ex.Message, ex.StackTrace));
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
                await Task.WhenAll(accountLockTask);
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.IsAccountLockedError, ex.Message, ex.StackTrace));
            }
        }

        /// <summary>
        /// Createss Network Share on NAS for new user.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public bool CreateNASFolder(string userName)
        {
            Task<bool> createNASTask = Task.Run(() => 
            {
                string folderName = string.Empty;
                string usersId = string.Empty;
                folderName = userName;
                string parentDirectory = _networkInfo.NetworkPath + folderName + @"\";

                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal userPrincipalUser = UserPrincipal.FindByIdentity(principalContext, IdentityType.SamAccountName, userName))
                        {
                            using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                            {
                                Directory.CreateDirectory(parentDirectory);
                                DirectoryInfo dirInfo = new DirectoryInfo(parentDirectory);
                                DirectorySecurity dirSec = new DirectorySecurity();
                                dirSec = dirInfo.GetAccessControl();
                                dirSec.SetAccessRuleProtection(false, false);
                                dirInfo.SetAccessControl(dirSec);
                                try
                                {
                                    dirSec.AddAccessRule(new FileSystemAccessRule(@"SUMMIT_NT\" + userName.Trim(), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                                    dirInfo.SetAccessControl(dirSec);
                                    //leaving here for debugging if NAS directory creation fails. Fixed issue due to user SID not working properly on 2012 and up servers.
                                    //_logger.LogInfo(string.Format(@"Folder Name: {0}. ParentDirectory: {1}. NetworkPath: {2}. UserName: {3}.", folderName, parentDirectory, _networkInfo.NetworkPath, userName));
                                }
                                catch
                                {
                                    usersId = userPrincipalUser.Sid.ToString();
                                    SecurityIdentifier secIdentifierSid = new SecurityIdentifier(usersId);
                                    dirSec.AddAccessRule(new FileSystemAccessRule(secIdentifierSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                                    dirInfo.SetAccessControl(dirSec);
                                    //_logger.LogInfo(string.Format(@"Folder Name: {0}. ParentDirectory: {1}. NetworkPath: {2}. User SID: {3}.", folderName, parentDirectory, _networkInfo.NetworkPath, usersId));
                                }
                            }
                        }
                    }

                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogInfo(string.Format(@"Folder Name: {0}. ParentDirectory: {1}. NetworkPath: {2}. User SID: {3}.", folderName, parentDirectory, _networkInfo.NetworkPath, usersId));
                    _logger.LogError(string.Format(ErrorMessages.NASCreationError, parentDirectory, ex.Message, ex.StackTrace));
                    return false;
                }
            });
            Task.WhenAll(createNASTask);
            return createNASTask.Result;
        }

        /// <summary>
        /// Maps drive to user's account.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public bool MapHomeFolder(string user, string driveLetter)
        {
            if (user != null)
            {
                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(principalContext, IdentityType.SamAccountName, user))
                        {
                            using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                            {
                                if (userPrincipal != null && principalContext != null)
                                {
                                    //added to try to find which server is causing problems for LDAP servers. Logs sucessful LDAP servers with no issues.
                                    _logger.LogInfo(string.Format(@"PrincipalContext: {0}", principalContext.ConnectedServer));
                                    userPrincipal.HomeDrive = driveLetter;
                                    userPrincipal.HomeDirectory = _networkInfo.NetworkPath + user.Trim() + @"\";
                                    userPrincipal.Save();

                                    return true;
                                }
                                else
                                {
                                    //added to try to find which server is causing problems for LDAP servers. Logs servers with problems.
                                    _logger.LogInfo(string.Format(@"PrincipalContext failed To Connect. Connected Server:{0}", principalContext.ConnectedServer));
                                    return false;
                                }
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogInfo(string.Format(@"User:{0}. DriveLetter: {2}. HomeDirectory: {3}. ", user, driveLetter, _networkInfo.NetworkPath + user.Trim() + @"\"));
                    _logger.LogError(string.Format(ErrorMessages.MapHomeFolderError, ex.Message, ex.StackTrace));
                }
            }
            return false;
        }

        /// <summary>
        /// Maps drive to user's account. This is for non-hybrid only.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public bool MapHomeFolder(WrapperModel wrapper, string driveLetter)
        {
            try
            {
                if (wrapper.User != null && !string.IsNullOrEmpty(wrapper.User.Username))
                {
                    using (PowerShell PowerShellInstance = PowerShell.Create())
                    {
                        PSCredential credential = new PSCredential(Environment.UserDomainName + @"\" + _impersonation.User, _impersonation.Password.ToSecureString());
                        PowerShellInstance.AddCommand("Set-Variable");
                        PowerShellInstance.AddParameter("Name", "cred");
                        PowerShellInstance.AddParameter("Value", credential);
                        PowerShellInstance.AddScript(string.Format(@"import-module activedirectory; Set-ADUser ""{0}"" -HomeDrive ""{1}"" -HomeDirectory ""{2}"" -Credential $cred;", wrapper.User.Username, driveLetter, _networkInfo.NetworkPath + wrapper.User.Username));
                        PowerShellInstance.AddArgument("runas");
                        Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                        if (PowerShellInstance.Streams.Error.Count > 0)
                        {
                            foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                            {
                                StringBuilder sb = new StringBuilder();
                                sb.AppendLine(error.Exception.Message);
                                _logger.LogError(sb.ToString());
                            }
                        }
                        else
                        {
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(string.Format(ErrorMessages.MapHomeFolderError, ex.Message, ex.StackTrace));
                return false;
            }
        }

        /// <summary>
        /// Gets Active Directory user from their user name. Made unique by SAM acct name. 
        /// </summary>
        /// <param name="displayName"></param>
        /// <returns></returns>
        public User GetADUserByDisplayName(string displayName)
        {
            return GetActiveDirectoryDisplayName(displayName);
        }

        /// <summary>
        /// Makes AD call to fetch User information.
        /// </summary>
        /// <param name="displayName"></param>
        /// <returns></returns>
        private User GetActiveDirectoryDisplayName(string displayName)
        {
            User activeDirectoryResults = new User();
            try
            {
                using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                {
                    using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, IdentityType.Name, displayName))
                    {
                        activeDirectoryResults.DisplayName = user.DisplayName;
                        activeDirectoryResults.PrincipalName = user.UserPrincipalName;
                        activeDirectoryResults.Username = user.SamAccountName;
                        activeDirectoryResults.DistinguishedName = user.DistinguishedName;

                        activeDirectoryResults.IsEnabled = user.Enabled;
                        activeDirectoryResults.JobDescription = user.Description;

                        using (DirectoryEntry entry = (DirectoryEntry)user.GetUnderlyingObject())
                        {
                            activeDirectoryResults.SiteName = entry.Properties["physicalDeliveryOfficeName"].Value != null ? entry.Properties["physicalDeliveryOfficeName"].Value.ToString() : "No office listed";

                            using (DirectoryEntry deUserContainer = entry.Parent)
                            {
                                activeDirectoryResults.OU = deUserContainer.Properties["DistinguishedName"].Value.ToString();
                            }

                            activeDirectoryResults.PhoneNumber = user.VoiceTelephoneNumber;
                            activeDirectoryResults.EmailAddress = user.EmailAddress;
                            activeDirectoryResults.LastLogOn = user.LastLogon;
                            activeDirectoryResults.BadLogOnCount = user.BadLogonCount;

                            using (PrincipalSearchResult<Principal> groups = user.GetGroups())
                            {
                                activeDirectoryResults.Groups = new List<ADPrincipalObject>();

                                foreach (Principal group in groups)
                                {
                                    activeDirectoryResults.Groups.Add(new ADPrincipalObject
                                    {
                                        Name = group.Name,
                                        DistinguishedName = group.DistinguishedName
                                    });
                                }
                            }
                        }
                    }
                }
                return activeDirectoryResults;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.GetAdUserByDisplayError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Uses AD to search using the unique identifier surname to find the last name of the User object.
        /// </summary>
        /// <param name="surname"></param>
        /// <returns>List</returns>
        public async Task<List<ADPrincipalObject>> SearchADByLastName(string surname)
        {
            Task<List<ADPrincipalObject>> usersTask = Task.Run(() =>
            {
                List<ADPrincipalObject> users = new List<ADPrincipalObject>();
                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal user = new UserPrincipal(principalContext))
                        {
                            user.Surname = surname;
                            using (PrincipalSearcher searcher = new PrincipalSearcher(user))
                            {
                                foreach (Principal found in searcher.FindAll())
                                {
                                    users.Add(new ADPrincipalObject
                                    {
                                        DistinguishedName = found.DistinguishedName,
                                        Name = found.Name
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.SearchADByLastNameError, ex.Message, ex.StackTrace));
                    throw;
                }
                return users;
            });
            await Task.WhenAll(usersTask);
            return usersTask.Result;
        }

        /// <summary>
        /// Gets a list of all users from AD.
        /// </summary>
        /// <returns>List<ADPrincipalObject></returns>
        public async Task<List<ADPrincipalObject>> GetAllUsers()
        {
            Task<List<ADPrincipalObject>> userTask = Task.Run(() =>
            {
                List<ADPrincipalObject> users = new List<ADPrincipalObject>();
                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal user = new UserPrincipal(principalContext))
                        {
                            using (PrincipalSearcher searcher = new PrincipalSearcher(user))
                            {
                                foreach (Principal found in searcher.FindAll())
                                {
                                    users.Add(new ADPrincipalObject
                                    {
                                        DistinguishedName = found.DistinguishedName,
                                        Name = found.Name
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.GetAllUsersError, ex.Message, ex.StackTrace));
                    throw;
                }
                return users;
            });
            await Task.WhenAll(userTask);
            return userTask.Result;
        }

        /// <summary>
        /// Searches AD by userName from the ADPrincipalObjects that have been passed into it. 
        /// </summary>
        /// <param name="name"></param>
        /// <returns>ADPrincipalObject</returns>
        public async Task<ADPrincipalObject> SearchADByName(string name)
        {
            Task<ADPrincipalObject> userTask = Task.Run(() =>
            {
                ADPrincipalObject selectedUser = new ADPrincipalObject();
                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (UserPrincipal user = new UserPrincipal(principalContext))
                        {
                            user.Name = name;
                            using (PrincipalSearcher searcher = new PrincipalSearcher(user))
                            {
                                foreach (Principal found in searcher.FindAll())
                                {
                                    selectedUser.Name = found.Name;
                                    selectedUser.DistinguishedName = found.DistinguishedName;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.SearchADByNameError, ex.Message, ex.StackTrace));
                    throw;
                }
                return selectedUser;
            });
            await Task.WhenAll(userTask);
            return userTask.Result;
        }

        /// <summary>
        /// Users Directory Searcher to get all OUs in AD and returns them in a list.
        /// </summary>
        /// <returns></returns>
        public async Task<List<string>> GetUserOUs()
        {
            Task<List<string>> ouTask = Task.Run(() =>
            {
                StringBuilder sb = new StringBuilder();
                try
                {
                    sb.Append("LDAP://");

                    for (int i = 0; i < _impersonation.Domain.Split('.').Length; i++)
                    {
                        sb.Append("DC=" + _impersonation.Domain.Split('.')[i]);
                        if (i < _impersonation.Domain.Split('.').Length)
                            sb.Append(",");
                    }

                    List<string> ous = new List<string>();

                    using (DirectoryEntry de = new DirectoryEntry(sb.ToString()))
                    {
                        using (DirectorySearcher directorySearcher = new DirectorySearcher("(objectCategory=organizationalUnit)"))
                        {
                            foreach (SearchResult item in directorySearcher.FindAll())
                            {
                                if (item.Path.StartsWith("LDAP://OU=Users"))
                                {
                                    ous.Add(item.Path.Substring(7));
                                }
                            }
                        }
                    }

                    return ous.OrderBy(x => x).ToList();
                }
                catch(Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.SearchADByNameError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            await Task.WhenAll(ouTask);
            return ouTask.Result;
        }

        /// <summary>
        /// Gets all OUs in AD and returns them in a list, this is for non hybrid enviroment.
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        public async Task<List<string>> GetUserOUs(string filter = "Users")
        {
            Task<List<string>> ouTask = Task.Run(() =>
            {
                try
                {
                    List<string> results = new List<string>();
                    using (PowerShell PowerShellInstance = PowerShell.Create())
                    {
                        PowerShellInstance.AddScript(string.Format(@"import-module activedirectory; Get-ADOrganizationalUnit -Filter ""Name -like '{0}'"";", filter));
                        Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                        if (PowerShellInstance.Streams.Error.Count > 0)
                        {
                            foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                            {
                                StringBuilder sb = new StringBuilder();
                                sb.AppendLine(error.Exception.Message);
                                _logger.LogError(sb.ToString());
                            }
                        }
                        if (PSOutput.Count > 0)
                        {
                            foreach (PSObject orgUnit in PSOutput)
                            {
                                if (!string.IsNullOrEmpty(orgUnit.Properties["DistinguishedName"].Value.ToString()))
                                {
                                    string temp = string.Empty;
                                    temp = orgUnit.Properties["DistinguishedName"].Value.ToString();
                                    results.Add(temp);
                                }
                            }
                        }

                        return results.OrderBy(x => x).ToList();
                    }
                }
                catch(Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.SearchADByNameError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            await Task.WhenAll(ouTask);
            return ouTask.Result;
        }

        /// <summary>
        /// Moves Users from one OU to another.
        /// </summary>
        /// <param name="oldOU"></param>
        /// <param name="newOU"></param>
        public void MoveUserToNewOU(string oldOU, string newOU)
        {
            Task moveUserTask = Task.Run(() =>
            {
                using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                {
                    try
                    {
                        DirectoryEntry CurrentLocation = new DirectoryEntry(@"LDAP://" + oldOU);
                        CurrentLocation.MoveTo(new DirectoryEntry(@"LDAP://" + newOU));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(string.Format(ErrorMessages.MoveUserToNewOUError, ex.Message, ex.StackTrace));
                        throw;
                    }
                }
            });
            Task.WhenAll(moveUserTask);
        }

        /// <summary>
        /// Moves User to new AD OU via powershell if in non hybrid enviroment, due to DC's being read only. Only Use this if in non-hybrid enviroment.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="newOU"></param>
        public async void MoveUserToNewOU(WrapperModel wrapper, string newOU)
        {
            Task moveUserTask = Task.Run(() =>
            {
                try
                {
                    using (PowerShell PowerShellInstance = PowerShell.Create())
                    {
                        PowerShellInstance.AddScript(string.Format(@"import-module activedirectory; Get-ADUser -Filter ""UserPrincipalName -eq '{0}'"";", wrapper.User.DistinguishedName));
                        Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                        if (PowerShellInstance.Streams.Error.Count > 0)
                        {
                            foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                            {
                                StringBuilder sb = new StringBuilder();
                                sb.AppendLine(error.Exception.Message);
                                _logger.LogError(sb.ToString());
                            }
                        }
                        if (PSOutput.Count > 0)
                        {
                            string userPrincipalName = PSOutput.FirstOrDefault().Properties["UserPrincipalName"].Value.ToString();
                            if (!string.IsNullOrEmpty(userPrincipalName))
                            {
                                using (PowerShell PowerShellInstanceTwo = PowerShell.Create())
                                {
                                    PSCredential credential = new PSCredential(Environment.UserDomainName + @"\" + _impersonation.User, _impersonation.Password.ToSecureString());
                                    PowerShellInstanceTwo.AddCommand("Set-Variable");
                                    PowerShellInstanceTwo.AddParameter("Name", "cred");
                                    PowerShellInstanceTwo.AddParameter("Value", credential);
                                    PowerShellInstanceTwo.AddScript(string.Format(@"import-module activedirectory; -Identity ""{0}"" -TargetPath ""{1}"" -Credential $cred;", userPrincipalName, newOU));
                                    PowerShellInstanceTwo.AddArgument("runas");
                                    Collection<PSObject> PSOutputTwo = PowerShellInstanceTwo.Invoke();
                                    if (PowerShellInstanceTwo.Streams.Error.Count > 0)
                                    {
                                        foreach (ErrorRecord error in PowerShellInstanceTwo.Streams.Error)
                                        {
                                            StringBuilder sb = new StringBuilder();
                                            sb.AppendLine(error.Exception.Message);
                                            _logger.LogError(sb.ToString());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch(Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.MoveUserToNewOUError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            await Task.WhenAll(moveUserTask);
        }

        /// <summary>
        /// Checks Active Directory if name is taken.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public async Task<bool> CheckUserNameAvailability(string userName)
        {
            Task<bool> userAvailabilityTask = Task.Run(() =>
            {
                bool available = false;
                if (!string.IsNullOrEmpty(userName))
                {
                    userName = userName.ToLower(CultureInfo.CurrentCulture);
                    try
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                        {
                            using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, userName))
                            {
                                available = user != null && user.SamAccountName == userName ? false : true;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(string.Format(ErrorMessages.CheckUserNameAvailabilityError, ex.Message, ex.StackTrace));
                        throw;
                    }
                }
                return available;
            });
            await Task.WhenAll(userAvailabilityTask);
            return userAvailabilityTask.Result;
        }

        /// <summary>
        /// Uses powershell to get Security Groups to refresh list.
        /// </summary>
        public Collection<PSObject> GetSecurityGroups()
        {
            Collection<PSObject> results = new Collection<PSObject>();
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript("import-module activedirectory; Get-ADGroup -SearchBase 'OU=Security Groups - Remote Offices,DC=ad,DC=sumg,DC=int' -Filter *; Select-Object DistinguishedName, Name; Sort-Object -Property Name;");
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine(error.Exception.Message);
                            _logger.LogError(sb.ToString());
                        }
                    }
                    if (PSOutput.Count > 0)
                    {
                        foreach (PSObject securitygroup in PSOutput)
                        {
                            if (securitygroup.Properties["DistinguishedName"].Value.ToString() != null && securitygroup.Properties["Name"].Value.ToString() != null)
                            {
                                results.Add(securitygroup);
                            }
                        }
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.PowershellError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Gets all sites from AD using powershell.
        /// </summary>
        /// <returns></returns>
        public Collection<PSObject> GetADSites()
        {
            Collection<PSObject> results = new Collection<PSObject>();
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript("import-module activedirectory; Get-ADOrganizationalUnit -SearchBase 'OU=Sites,DC=ad,DC=sumg,DC=int' -SearchScope Subtree -Filter *;");
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine(error.Exception.Message);
                            _logger.LogError(sb.ToString());
                        }
                    }
                    if (PSOutput.Count > 0)
                    {
                        results = PSOutput;
                    }
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.PowershellError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Uses windows credentials for ldap authentication to determine if user can access data.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public bool LDAPAuthentication(string userName, string password)
        {
            using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain))
            {
                using (principalContext)
                {
                    bool results = principalContext.ValidateCredentials(userName, password);

                    return results;
                }
            }
        }

        /// <summary>
        /// Allows password to be changed using Active Directory.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public bool ChangeUserPassword(string samAccountName, string password)
        {
            using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
            {
                using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                {
                    using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, IdentityType.SamAccountName, samAccountName))
                    {
                        try
                        {
                            user.SetPassword(password);
                            return true;
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Gets list of all computers from Active Directory.
        /// </summary>
        /// <returns>string array computerList</returns>
        public string[] GetComputersFromActiveDirectory()
        {
            string domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            List<string> stringList = new List<string>();

            try
            {
                DirectoryEntry searchRoot = new DirectoryEntry("LDAP://" + domainName);
                DirectorySearcher directorySearcher = new DirectorySearcher(searchRoot);
                directorySearcher.Filter = "(objectClass=computer)";
                directorySearcher.SizeLimit = int.MaxValue;
                directorySearcher.PageSize = int.MaxValue;

                foreach (SearchResult searchResult in directorySearcher.FindAll())
                {
                    string name = searchResult.GetDirectoryEntry().Name;

                    if (name.StartsWith("CN="))
                    {
                        string adComputer = name.Remove(0, "CN=".Length);
                        stringList.Add(adComputer);
                    }

                    directorySearcher.Dispose();
                    searchRoot.Dispose();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.LDAPConnectionError, ex.Message, ex.StackTrace));
                throw;
            }

            string[] computerList = stringList.ToArray();
            Array.Sort(computerList);

            return computerList;
        }

        /// <summary>
        /// Gets all computers from AD using powershell.
        /// </summary>
        /// <param name="filter"></param>
        /// <returns></returns>
        public string [] GetComputersFromActiveDirectory(string filter ="*")
        {
            try
            {
                List<string> results = new List<string>();
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript(string.Format(@"import-module activedirectory; Get-ADComputer -Filter ""Name -like '{0}'"";", filter));
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in PowerShellInstance.Streams.Error)
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine(error.Exception.Message);
                            _logger.LogError(sb.ToString());
                        }
                    }
                    if (PSOutput.Count > 0)
                    {
                        foreach (PSObject orgUnit in PSOutput)
                        {
                            if (!string.IsNullOrEmpty(orgUnit.Properties["Name"].Value.ToString()))
                            {
                                string temp = string.Empty;
                                temp = orgUnit.Properties["Name"].Value.ToString();
                                results.Add(temp);
                            }
                        }
                    }

                    string[] computers = results.ToArray();
                    Array.Sort(computers);

                    return computers;
                }
            }
            catch(Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.LDAPConnectionError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        ///  Disables User account and removes any groups that account is joined to. 
        /// </summary>
        /// <param name="user"></param>
        public void DisableUserAndRemoveFromGroups(WrapperModel wrapper)
        {
            Task DisableAccountTask = Task.Run(() =>
            {
                using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                {
                    if (wrapper.User != null)
                    {
                        try
                        {
                            using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                            {
                                foreach (ADPrincipalObject group in wrapper.User.Groups)
                                {
                                    if (group.Name != "Domain Users" && group.DistinguishedName != null)
                                    {
                                        using (GroupPrincipal adGroup = GroupPrincipal.FindByIdentity(principalContext, group.DistinguishedName))
                                        {
                                            adGroup.Members.Remove(principalContext, IdentityType.DistinguishedName, wrapper.User.DistinguishedName);
                                            adGroup.Save();
                                        }
                                    }
                                }
                                using (UserPrincipal adUser = UserPrincipal.FindByIdentity(principalContext, wrapper.User.DistinguishedName))
                                {
                                    adUser.Enabled = false;
                                    adUser.Save();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(string.Format(ErrorMessages.DisableUserAndRemoveFromGroupsError, ex.Message, ex.StackTrace));
                            throw;
                        }
                    }
                }
            });
            Task.WhenAll(DisableAccountTask);
        }

        /// <summary>
        /// Re-enables user account.
        /// </summary>
        /// <param name="reEnableUser"></param>
        public void ReEnableExistingUser(WrapperModel wrapper)
        {
            Task reenableUserTask = Task.Run(() =>
            {
                using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                {
                    try
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                        {
                            using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, wrapper.User.DistinguishedName))
                            {
                                user.Enabled = true;
                                user.Description = wrapper.User.JobDescription;
                                user.SetPassword(wrapper.User.UserPassword);
                                user.ExpirePasswordNow();
                                user.VoiceTelephoneNumber = wrapper.User.PhoneNumber;
                                DirectoryEntry entry = (DirectoryEntry)user.GetUnderlyingObject();
                                entry.Properties["title"].Value = wrapper.User.JobDescription;

                                if (wrapper.User.Manager != null)
                                {
                                    entry.Properties["manager"].Value = wrapper.User.Manager.DistinguishedName;
                                }

                                entry.Properties["physicalDeliveryOfficeName"].Value = wrapper.User.SiteName;
                                entry.CommitChanges();
                                user.Save();
                                entry.Dispose();
                            }
                            foreach (ADPrincipalObject item in wrapper.User.Groups)
                            {
                                using (GroupPrincipal gp = GroupPrincipal.FindByIdentity(principalContext, item.Name))
                                {
                                    if (item.Name != "Domain Users")
                                    {
                                        using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, wrapper.User.DistinguishedName))
                                        {
                                            if (user != null)
                                            {
                                                if ((!user.IsMemberOf(gp)))
                                                {
                                                    gp.Members.Add(principalContext, IdentityType.SamAccountName, wrapper.User.Username);
                                                }
                                                else
                                                {
                                                    gp.Members.Remove(principalContext, IdentityType.SamAccountName, wrapper.User.Username);
                                                    gp.Members.Add(principalContext, IdentityType.SamAccountName, wrapper.User.Username);
                                                }
                                            }
                                        }
                                    }
                                    gp.Save();
                                }
                            }
                        }
                    }
                    catch (PrincipalExistsException ex)
                    {
                        _logger.LogError(string.Format(ErrorMessages.ReEnableExistingUserError, ex.Message, ex.StackTrace));
                        throw;
                    }
                }
            });
            Task.WhenAll(reenableUserTask);
        }

        /// <summary>
        /// Deletes user account.
        /// </summary>
        /// <param name="wrapper"></param>
        public void DeleteExistingUser(WrapperModel wrapper)
        {
            Task deleteUserTask = Task.Run(() =>
            {
                using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                {
                    try
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                        {
                            using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, wrapper.User.DistinguishedName))
                            {
                                if (user != null)
                                {
                                    user.Delete();
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(string.Format(ErrorMessages.DeleteExistingUserError, ex.Message, ex.StackTrace));
                        throw;
                    }
                }
            });
            Task.WhenAll(deleteUserTask);
        }

        /// <summary>
        /// Removes User from selected Active Directory groups.
        /// </summary>
        /// <param name="userDistinguishedName"></param>
        /// <param name="groups"></param>
        public void RemoveUserFromGroups(WrapperModel wrapper)
        {
            Task removeGroupTask = Task.Run(() =>
            {
                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                        {
                            foreach (ADPrincipalObject group in wrapper.ADPrincipalObjectGroups)
                            {
                                using (GroupPrincipal adGroup = GroupPrincipal.FindByIdentity(principalContext, group.DistinguishedName))
                                {
                                    adGroup.Members.Remove(principalContext, IdentityType.DistinguishedName, wrapper.UserDistinguishedName);
                                    adGroup.Save();
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.RemoveUsersFromGroupError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            Task.WhenAll(removeGroupTask);
        }

        /// <summary>
        /// Replaces existing groups with new groups. Used when re-enabling accounts.
        /// </summary>
        /// <param name="userDistinguishedName"></param>
        /// <param name="groups"></param>
        public void ReplaceUsersCurrentGroupWithNewGroup(WrapperModel wrapper)
        {
            Task replaceGroupsTask = Task.Run(() =>
            {
                try
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                        {
                            foreach (ADPrincipalObject group in wrapper.ADPrincipalObjectGroups)
                            {
                                using (GroupPrincipal adGroup = GroupPrincipal.FindByIdentity(principalContext, group.DistinguishedName))
                                {
                                    using (UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(principalContext, wrapper.User.Username))
                                    {
                                        if ((!userPrincipal.IsMemberOf(adGroup)))
                                        {
                                            adGroup.Members.Add(principalContext, IdentityType.DistinguishedName, wrapper.UserDistinguishedName);
                                        }
                                        else
                                        {
                                            adGroup.Members.Remove(principalContext, IdentityType.DistinguishedName, wrapper.UserDistinguishedName);
                                            adGroup.Members.Add(principalContext, IdentityType.DistinguishedName, wrapper.UserDistinguishedName);
                                        }
                                    }
                                    adGroup.Save();
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.ReplaceUsersCurrentGroupError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            Task.WhenAll(replaceGroupsTask);
        }

        /// <summary>
        /// Updates job description for AD Object.
        /// </summary>
        /// <param name="userDistinguishedName"></param>
        /// <param name="jobDescription"></param>
        public void UpdateUserJobDescription(string userDistinguishedName, string jobDescription)
        {
            Task updateUserJobDesc = Task.Run(() =>
            {
                try
                {
                    using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                        {
                            using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, userDistinguishedName))
                            {
                                user.Description = jobDescription;
                                DirectoryEntry entry = (DirectoryEntry)user.GetUnderlyingObject();
                                entry.Properties["title"].Value = jobDescription;
                                entry.CommitChanges();
                                user.Save();
                                entry.Dispose();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.UpdateUserJobDescriptionError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            Task.WhenAll(updateUserJobDesc);
        }

        /// <summary>
        /// Updates site in Active Directory.
        /// </summary>
        /// <param name="userDistinguishedName"></param>
        /// <param name="phone"></param>
        /// <param name="office"></param>
        /// <param name="managerDistinguishedName"></param>
        public void UpdateUserSiteInfo(string userDistinguishedName, string phone, string office, string managerDistinguishedName)
        {
            Task updateUserSiteTask = Task.Run(() =>
            {
                try
                {
                    using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                        {
                            using (UserPrincipal user = UserPrincipal.FindByIdentity(principalContext, userDistinguishedName))
                            {
                                user.VoiceTelephoneNumber = phone;
                                DirectoryEntry entry = (DirectoryEntry)user.GetUnderlyingObject();
                                entry.Properties["manager"].Value = managerDistinguishedName;
                                entry.Properties["physicalDeliveryOfficeName"].Value = office;
                                entry.CommitChanges();
                                user.Save();
                                entry.Dispose();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(string.Format(ErrorMessages.UpdateUserSiteInfoError, ex.Message, ex.StackTrace));
                    throw;
                }
            });
            Task.WhenAll(updateUserSiteTask);
        }

        /// <summary>
        /// Uses User values to create User object in AD.
        /// </summary>
        /// <param name="newUser"></param>
        public void CreateNewUser(WrapperModel wrapper)
        {
            try
            {
                Task userCreationTask = Task.Run(() =>
                {
                    if (wrapper.User != null)
                    {
                        using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain, wrapper.User.OU))
                        {
                            using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                            {
                                using (UserPrincipal userPrincipal = new UserPrincipal(principalContext))
                                {
                                    userPrincipal.GivenName = wrapper.User.FirstName;
                                    if (!string.IsNullOrEmpty(wrapper.User.MiddleInitial))
                                        userPrincipal.MiddleName = wrapper.User.MiddleInitial;
                                    userPrincipal.Surname = wrapper.User.LastName;
                                    userPrincipal.DisplayName = wrapper.User.DisplayName;
                                    userPrincipal.Name = wrapper.User.DisplayName;
                                    userPrincipal.SamAccountName = wrapper.User.Username;
                                    userPrincipal.UserPrincipalName = wrapper.User.Username + GeneralMessages.CompanyEmail;
                                    if (!string.IsNullOrEmpty(wrapper.User.JobDescription))
                                        userPrincipal.Description = wrapper.User.JobDescription;
                                    else
                                        userPrincipal.Description = "No Description";
                                    userPrincipal.SetPassword(wrapper.User.UserPassword);
                                    userPrincipal.VoiceTelephoneNumber = wrapper.User.PhoneNumber;
                                    if (!string.IsNullOrEmpty(wrapper.User.EmployeeId))
                                        userPrincipal.EmployeeId = wrapper.User.EmployeeId;
                                    userPrincipal.Enabled = true;
                                    userPrincipal.ExpirePasswordNow();
                                    userPrincipal.Save();

                                    if (userPrincipal.GetUnderlyingObjectType() == typeof(DirectoryEntry))
                                    {
                                        using (DirectoryEntry entry = (DirectoryEntry)userPrincipal.GetUnderlyingObject())
                                        {

                                            /* PWM 8/20/2025 - Set userAccountControl property to 
                                             * NORMAL_ACCOUNT = 512.  We set it explicitly to 
                                               prevent its being set to its default value of
                                               PASSWD_NOTREQD = 32 */

                                            entry.Properties["userAccountControl"].Value = 512;

                                            entry.Properties["physicalDeliveryOfficeName"].Value = wrapper.User.SiteName;
                                            if (!string.IsNullOrEmpty(wrapper.User.MiddleInitial))
                                                entry.Properties["initials"].Value = wrapper.User.MiddleInitial;
                                            if (!string.IsNullOrEmpty(wrapper.User.JobDescription))
                                                entry.Properties["title"].Value = wrapper.User.JobDescription;
                                            else
                                                entry.Properties["title"].Value = "No Description";
                                            if (wrapper.User.SiteName != "Floater Pool" || wrapper.User.SiteName != "NonSummit Accounts")
                                                entry.Properties["company"].Value = wrapper.User.Company;
                                            if (wrapper.User.Manager.DistinguishedName != null)
                                                entry.Properties["manager"].Value = wrapper.User.Manager.DistinguishedName;
                                            if (!string.IsNullOrEmpty(wrapper.User.Department))
                                                entry.Properties["department"].Value = wrapper.User.Department;
                                            entry.CommitChanges();
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
                Task.WhenAll(userCreationTask);
            }
            catch(Exception ex)
            {
                _logger.LogError(string.Format(ErrorMessages.CreateUserError, ex.Message, ex.StackTrace));
                throw;
            }
        }

        /// <summary>
        /// Checks user groups based unique id and adds them to the User object.
        /// </summary>
        /// <param name="user"></param>
        public void AddUserToGroups(WrapperModel wrapper)
        {
            Task addUserToGroupsTask = Task.Run(() =>
            {
                if (wrapper.User != null)
                {
                    using (PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, _impersonation.Domain))
                    {
                        using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                        {
                            foreach (ADPrincipalObject item in wrapper.User.Groups)
                            {
                                try
                                {
                                    using (GroupPrincipal gp = GroupPrincipal.FindByIdentity(principalContext, IdentityType.DistinguishedName, item.DistinguishedName))
                                    {
                                        if (gp != null)
                                        {
                                            Task.Delay(500);
                                            gp.Members.Add(principalContext, IdentityType.SamAccountName, wrapper.User.Username);
                                            gp.Save();
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError(string.Format(ErrorMessages.AddUserToGroupsError, ex.Message, ex.StackTrace));
                                    throw;
                                }
                            }
                        }
                    }
                }
            });
            Task.WhenAll(addUserToGroupsTask);
        }

        /// <summary>
        /// Move users that are newly disabled, to the Disabled OU.
        /// </summary>
        /// <param name="wrapper"></param>
        public void MoveUsersToDisabledOU(string oldOU)
        {
            string month = GenerateOUMonth();
            string combinedOU = string.Format(@"OU={0},OU={1},{2}", month, DateTime.Now.Year, _networkInfo.ADPath);
            Task moveUserTask = Task.Run(() =>
            {
                using (ImpersonatedUser impersonation = new ImpersonatedUser(_impersonation.User, _impersonation.Domain, _impersonation.Password))
                {
                    try
                    {
                        DirectoryEntry CurrentLocation = new DirectoryEntry(@"LDAP://" + oldOU);
                        CurrentLocation.MoveTo(new DirectoryEntry(@"LDAP://" + combinedOU));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(string.Format(ErrorMessages.MoveUserToNewOUError, ex.Message, ex.StackTrace));
                        throw;
                    }
                }
            });
            Task.WhenAll(moveUserTask);
        }

        /// <summary>
        /// Determines proper OU name due to restructure.
        /// </summary>
        /// <returns></returns>
        private string GenerateOUMonth()
        {
            string result = string.Empty;

            switch (DateTime.Now.Month.ToString())
            {
                case "1":
                    result = @"01-January";
                    break;
                case "2":
                    result = @"02-Feburary";
                    break;
                case "3":
                    result = @"03-March";
                    break;
                case "4":
                    result = @"04-April";
                    break;
                case "5":
                    result = @"05-May";
                    break;
                case "6":
                    result = @"06-June";
                    break;
                case "7":
                    result = @"07-July";
                    break;
                case "8":
                    result = @"08-August";
                    break;
                case "9":
                    result = @"09-September";
                    break;
                case "10":
                    result = @"10-October";
                    break;
                case "11":
                    result = @"11-November";
                    break;
                case "12":
                    result = @"12-December";
                    break;
                default:
                    result = "Unknown";
                    break;
            }

            return result;
        }
    }
}