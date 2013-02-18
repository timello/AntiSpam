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

package Bugzilla::Extension::AntiSpam::WebService::User;

use strict;
use base qw(Bugzilla::WebService::User);

use Bugzilla::Extension::AntiSpam::Util qw(login_to_extern_id);

sub get {
    my ($self, $params) = @_;

    my $result = $self->SUPER::get($params);

    foreach my $user (@{ $result->{users} || [] }) {
        $user->{name} = login_to_extern_id($user->{name});
    }

    return $result;
}

1;
