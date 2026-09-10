/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdint.h>

#include "fuzzing.h"
#include "ogs-proto.h"

#define kMaxInputLength 4096

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{ /* open5gs/lib/proto/dhcpv6.c */
    ogs_dhcpv6_message_t message;
    uint8_t buf[2048];

    if (Size > kMaxInputLength) {
        return 1;
    }

    if (!initialized) {
        initialize();
    }

    if (ogs_dhcpv6_parse(&message, Data, Size) == OGS_OK)
        ogs_dhcpv6_build(&message, buf, sizeof(buf));

    return 0;
}
