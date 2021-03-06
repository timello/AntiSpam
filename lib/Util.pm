# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is the AntiSpam Bugzilla Extension.
#
# The Initial Developer of the Original Code is Tiago Mello
# Portions created by the Initial Developer are Copyright (C) 2012 the
# Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Tiago Mello <timello@bugzilla.org>

package Bugzilla::Extension::AntiSpam::Util;
use strict;

use Bugzilla::Util qw(trick_taint);
use Bugzilla::User qw(login_to_id);
use Bugzilla::User::Setting qw(get_all_settings);


use base qw(Exporter);
@Bugzilla::Extension::AntiSpam::Util::EXPORT = qw(
    login_to_extern_id
    extern_id_to_login
);

sub login_to_extern_id {
    my ($login) = @_;
    my $dbh = Bugzilla->dbh;

    return '' if !$login;

    my $user_id = login_to_id($login);
    my $setting = get_all_settings($user_id)->{hide_email_address};

    my $extern_id = $dbh->selectrow_array(
        "SELECT extern_id FROM profiles 
            WHERE userid = ?", undef, $user_id);

    if ($extern_id and $setting->{value} eq 'on') {
        return $extern_id;
    }

    return $login;
}

sub extern_id_to_login {
    my ($extern_id) = @_;
    my $dbh = Bugzilla->dbh;

    return '' if !$extern_id;

    trick_taint($extern_id);
    my $login = $dbh->selectrow_array('SELECT login_name FROM profiles
                                       WHERE extern_id = ?',
                                      undef, $extern_id);
    return $login || '';
}

1;
