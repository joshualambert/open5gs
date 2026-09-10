# Copyright (C) 2026 by Josh Lambert <josh.lambert@alabamalightwave.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

testapp_ipv6_pd_sources = files('''
    abts-main.c
    pd-scenario.c
    epc-test.c
    5gc-test.c
'''.split())

testapp_ipv6_pd_exe = executable('ipv6-pd',
    sources : testapp_ipv6_pd_sources,
    c_args : testunit_core_cc_flags,
    dependencies : libtestapp_dep)

# Many scenarios wait up to 3 s per missing reply; allow for a slow CI.
test('ipv6-pd', testapp_ipv6_pd_exe,
    is_parallel : false, suite: 'app', timeout : 300)
