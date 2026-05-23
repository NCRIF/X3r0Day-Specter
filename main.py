##################################################################################
# Part of X3r0Day Project. See LICENSE for licensing information.
# GNU General Public License v3.0
##################################################################################

"""
compatibility shim for repo-local execution
"""

from specter.cli import main


if __name__ == "__main__":
    raise SystemExit(main(prog="python3 main.py"))
