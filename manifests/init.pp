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
  $sudo_content = @(EOT)
    Defaults mailto = "${adminemail}"
    Defaults lecture = always,use_pty,requiretty,mail_always,log_host
    Defaults env_keep += "HISTTIMEFORMAT HISTFILE HISTFILESIZE" \# bash
    Defaults env_keep += "histfile history savehist" \# tcsh
    Defaults env_keep += "HISTORY SAVEHIST\" \# tcsh
    Defaults env_keep += "EXTENDED_HISTORY HISTSIZE SAVEHIST" \# zsh
    | EOT
  $impersonators = []
  $impersonatees = []

  $alias_array = [$sudo_content]
  $impersonation.each | $impe | {
    $group_name = $impe[0]
    if $impe[1][impersonatorusers] {
      $impersonatorusers = $impe[1][impersonatorusers]
    }
    if $impe[1][impersonatorgroups] {
      $impersonatorgroups = $impe[1][impersonatorgroups]
    }
    if $impe[1][impersonateeusers] {
      $impersonateeusers = $impe[1][impersonateeusers]
    }
    if $impe[1][impersonateegroups] {
      $impersonateegroups = $impe[1][impersonateegroups]
    }
    if $impe[1][notimpersonateeusers] {
      $notimpersonateeusers = $impe[1][notimpersonateeusers]
    }
    if $impe[1][notimpersonateegroups] {
      $notimpersonateegroups = $impe[1][notimpersonateegroups]
    }
    if $impe[1][notimpersonatorusers] {
      $notimpersonatorusers = $impe[1][notimpersonatorusers]
    }

    #if (!$impersonateeusers or !$impersonateegroups) {
    #}

    #if (!$impersonatorusers or !$impersonatorgroups) {
    #  fail("No Impersonter users or groups defined")
    #}

    if $impersonatorgroups {
      $impersonatorgroups.each |$impgroup| {
        pam_access::entry { "Allow sudo for group ${impgroup}":
          group      => $impgroup,
          origin     => 'LOCAL',
          permission => '+',
          position   => '-1',
        }
      }
      $impersonatorgroups.each | $impgroup| {
      $impersonators << "%${impgroup}"
      }
    }
    if $impersonatorusers {
      $impersonatorusers.each | $impuser| {
        pam_access::entry { "Allow sudo for user ${impuser}":
          user       => $impuser,
          origin     => 'LOCAL',
          permission => '+',
          position   => '-1',
        }
      }
      $impersonatorusers.each | $impuser| {
      $impersonators << $impuser
      }
    }
    if $notimpersonatorusers {
      $notimpersonatorusers.each | $impuser| {
        pam_access::entry { "Deny sudo for user ${impuser}":
          user       => $impuser,
          origin     => 'LOCAL',
          permission => '-',
          position   => '-1',
        }
      }
      $notimpersonatorusers.each | $impuser| {
      $impersonators << "!${impuser}"
      }
    }

    if $notimpersonatorgroups {
      $notimpersonatorgroups.each | $impgroup| {
        pam_access::entry { "Deny sudo for groups ${impgroup}":
          group      => $impgroup,
          origin     => 'LOCAL',
          permission => '-',
          position   => '-1',
        }
      }
      $notimpersonatorgroups.each | $impgroup| {
      $impersonators << "!%${impgroup}"
      }
    }

    if $impersonateeusers {
      $impersonateeusers.each | $impuser| {
        $impersonatees << $impuser
      }
    }
    if $impersonateegroups {
      $impersonateegroups.each | $impgroup| {
        $impersonatees << "%${impgroup}"
      }
    }
    if $notimpersonateeusers {
      $notimpersonateeusers.each | $impuser| {
        $impersonatees << "!${impuser}"
      }
    }
    if $notimpersonateegroups {
      $notimpersonateegroups.each | $impgroup| {
        $impersonatees << "!%${impgroup}"
      }
    }
    $impersonatoralias = join($impersonators,',')
    $impersonateealias = join($impersonatees,',')
    $alias_array << "User_Alias ${group_name}_IMPERSONATOR = ${impersonatoralias}"
    $alias_array = $alias_array + ["Runas_Alias ${group_name}_IMPERSONATEE = ${impersonateealias}"]
    $alias_array = $alias_array + ["${group_name}_IMPERSONATOR = (${group_name}_IMPERSONATEE)"]
    $alias_array = $alias_array + ["NOPASSWD: LOG_OUTPUT: LOG_INPUT: /bin/bash -l,/usr/bin/tcsh -l,i\\"]
    $alias_array = $alias_array + ["/bin/bash,/usr/bin/tcsh, /usr/bin/zsh,/usr/bin/zsh -l"]
  }
  profile_sudo::configs { 'Impersonate':
      content  => join([$sudo_content,join($alias_array,"\n")],"\n"),
      priority => 10,
  }
}
