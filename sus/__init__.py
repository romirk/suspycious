"""
Suspycious
~~~~~~~~~~

Suspycious is an implementation of the SUS protocol, written in Python.
It is designed to be fast, secure, and easy to use. This is an official
reference implementation of the SUS protocol.
"""

# Copyright (C) 2023 Romir Kulshrestha
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__all__ = ["SusClient", "SusServer"]
__license__ = "AGPL-3.0-or-later"

from sus.client import SusClient
from sus.server import SusServer
