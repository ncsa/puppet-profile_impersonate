# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include profile_impersonate
class profile_impersonate (
  Hash $impersonaters,
  Hash $imposterable,
) {

    $impersonaters.each {
      pam_access::entry { "Allow sudo for group ${impersonaters}":
        group       => $impersonater,
        origin     => 'LOCAL',
        permission => '+',
        position   => '-1',
    }

    }
}
