! AntiCSRF.py Simple CSRF Protection
! Copyright (C) 2017 Cat Stevens
!
! This program is free software: you can redistribute it and/or modify
! it under the terms of the GNU General Public License as published by
! the Free Software Foundation, either version 3 of the License, or
! (at your option) any later version.
!
! This program is distributed in the hope that it will be useful,
! but WITHOUT ANY WARRANTY; without even the implied warranty of
! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
! GNU General Public License for more details.
!
! You should have received a copy of the GNU General Public License
! along with this program.  If not, see <http://www.gnu.org/licenses/>.
USING: arrays calendar hashtables kernel math math.parser random
sequences words ;
IN: anticsrf

CONSTANT: default-token-expiry 3600000000 ! 1 hour in microseconds
CONSTANT: default-token-length 42

: micro-now ( -- since-epoch )
  now duration>microseconds ;

: random-key ( length -- key )
  2 /i random-bytes [
    >hex
    [ length 1 = "0" "" ? ] keep
    append
  ] { } map-as
  "" join ;

TUPLE: csrf-clerk
  { current-tokens hashtable }
  { expired-tokens hashtable }
  { expire-after   integer }
  { key-length     integer }
  { key-gen        word    initial: random-key }
  { autoclean      boolean initial: t }
  { clear-next     boolean initial: f } ; final

<PRIVATE

PRIVATE>

: register-new-token ( clerk -- token )
  1 ;

GENERIC: unregister-token ( clerk token/s -- count/? )

M: array unregister-token
  [ unregister-token 1 0 = ] with map sum ;

M: hashtable unregister-token
  2drop t ;

: clean-expired-tokens ( clerk -- count ) drop ;

GENERIC: valid-token? ( clerk token -- ? )

M: array valid-token?
  ;

M: hashtable valid-token?
  ;

GENERIC: unexpire-token ( clerk token -- newly-valid )

M: array unexpire-token
  ;

M: hashtable unexpire-token
  ;

