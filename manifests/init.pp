# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include profile_impersonate
class profile_impersonate (
  Hash $impersonation,
  String $adminemail,
) {
    $sudo_content =  "Defaults mailto = \"${adminemail}\"
      Defaults lecture = always,use_pty,requiretty,mail_always,log_host
      Defaults env_keep += \"HISTTIMEFORMAT HISTFILE HISTFILESIZE\" # bash
      Defaults env_keep += \"histfile history savehist\" # tcsh
      Defaults env_keep += \"HISTORY SAVEHIST\" # tcsh
      Defaults env_keep += \"EXTENDED_HISTORY HISTSIZE SAVEHIST\" # zsh
    "
    $alias_array = [$sudo_content]
    $impersonation.each | $impe | {
      $group_name = $impe[0]
      $impersonatorusers = $impe[1][impersonatorusers]
      $impersonatorgroups = $impe[1][impersonatorgroups]
      $impersonateeusers = $impe[1][impersonateeusers]
      $impersonateegroups = $impe[1][impersonateegroups]
      $notimpersonateeusers = $impe[1][notimpersonateeusers]
      $notimpersonateegroups = $impe[1][notimpersonateegroups]
      $notimpersonatorusers = $impe[1][notimpersonatorusers]

      $impersonatergroup.each |$impgroup| {
        pam_access::entry { "Allow sudo for group ${impgroup}":
          group      => $impgroup,
          origin     => 'LOCAL',
          permission => '+',
          position   => '-1',
        }
      }
      $impersonateruser.each | $impuser| {
        pam_access::entry { "Allow sudo for user ${impuser}":
          user       => $impuser,
          origin     => 'LOCAL',
          permission => '+',
          position   => '-1',
        }
      }
      $notimpersonateruser.each | $impuser| {
        pam_access::entry { "Deny sudo for user ${impuser}":
          user       => $impuser,
          origin     => 'LOCAL',
          permission => '-',
          position   => '-1',
        }
      }
      $impersonators = []
      $impersonatees = []

      $impersonatorusers.each | $impuser| {
        $impersonators << $impuser
      }
      $impersonatorgroups.each | $impgroup| {
        $impersonators << "%${impgroup}"
      }
      $impersonateeusers.each | $impuser| {
        $impersonatees << $impuser
      }
      $impersonateegroups.each | $impgroup| {
        $impersonatees << "%${impgroup}"
      }
      $notimpersonateeusers.each | $impuser| {
        $impersonatees << "!${impuser}"
      }
      $notimpersonateegroups.each | $impgroup| {
        $impersonatees << "!%${impgroup}"
      }
      $notimpersonatorusers.each | $impuser| {
        $impersonators << "!${impuser}"
      }

      $impersonatoralias = join($impersonators,',')
      $impersonateealias = join($impersonatees,',')
      $alias_array = $alias_array + ["User_Alias ${group_name}_IMPERSONATOR = ${impersonatoralias}"]
      $alias_array = $alias_array + ["Runas_Alias ${group_name}_IMPERSONATEE = ${impersonateealias}"]
      $alias_array << "${group_name}_IMPERSONATOR = (${group_name}_IMPERSONATEE) \
        NOPASSWD: LOG_OUTPUT: LOG_INPUT: /bin/bash -l,/usr/bin/tcsh -l,\
        /bin/bash,/usr/bin/tcsh, /usr/bin/zsh,/usr/bin/zsh -l"
    }
    profile_sudo::configs { 'Impersonate':
      content  => join([$sudo_content,join($alias_array,"\n")],"\n"),
      priority => 10,
    }
}
