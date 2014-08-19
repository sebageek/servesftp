#!/usr/bin/env python2
from __future__ import print_function

__version__ = "0.1"

import argparse
import os
import sys

from twisted import cred
from twisted.internet import defer, protocol
from twisted.cred import portal, checkers
from twisted.conch import avatar, interfaces as conchinterfaces, checkers as conchcheckers
from twisted.conch.ssh import filetransfer, session, factory
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
from twisted.python import components
from twisted.conch.ssh.keys import Key
from twisted.conch.ls import lsLine
from zope.interface import implements

# TODO: Config? Directory?

# Hostkeys: use from commandline
#               if none specified: look inside config dir
#               if none present: generate, save to config dir
#               if keys cannot be written to ~/.servesftp/id_rsa{,.pub}, warn user, continue


# TODO:
#	ssh handling (wirft ne exception)
#	symbolische links, ..
#		symlink outside of chroot?
#	umask, default /?
#	cleanup
#		pathkram geradeziehen
#		fix ALL the imports
#	error messages
#		better exceptions
#		try to report things back to the user, how does twisted do this?
#	is "none" auth somehow possible?


class SSHUnavailableProtocol(protocol.Protocol):
	def connectionMade(self):
		self.transport.write("This SSH server runs SFTP only!\r\n")

	def dataReceived(self, bytes):
		pass

	def connectionLost(self, reason):
		pass

class LimitedSFTPAvatar(avatar.ConchUser):
	implements(conchinterfaces.ISession)

	def __init__(self, chroot):
		print("Init SFTPAvatar (%s)" % (self))
		avatar.ConchUser.__init__(self)
		self.channelLookup['session'] = session.SSHSession
		self.subsystemLookup['sftp'] = filetransfer.FileTransferServer

		self.chroot = chroot

	def getBaseDir(self):
		return os.path.join(os.getcwd(), self.chroot)

	def openShell(self, protocol):
		unavailableprotocol = SSHUnavailableProtocol()
		protocol.makeConnection(session.wrapProtocol(unavailableprotocol))
		unavailableprotocol.makeConnection(protocol)
		protocol.loseConnection()

	def getPty(self, terminal, windowSize, attrs):
		return None

	def execCommand(self, protocol, cmd):
		print("User tried to exec command '%s'" % (cmd,))
		self.openShell(protocol)

	def closed(self):
		print("Avatar closed")

	def windowChanged(self, newWindowSize):
		pass
	
	def eofReceived(self):
		pass


class LimitedSFTPServer:
	implements(conchinterfaces.ISFTPServer)

	def __init__(self, avatar, allowWrite=True):
		self.allowWrite = allowWrite
		self.avatar = avatar
		self.chroot = avatar.getBaseDir()
		if not self.chroot.endswith("/"):
			self.chroot = self.chroot + "/"
		print("Initialized LimitedSFTPServer() for directory", self.chroot)

	def isWritable(self):
		return self.allowWrite

	@staticmethod
	def _statToAttrs(s):
		return {
			"size" : s.st_size,
			"uid" : s.st_uid,
			"gid" : s.st_gid,
			"permissions" : s.st_mode,
			"atime" : int(s.st_atime),
			"mtime" : int(s.st_mtime)
		}

	def gotVersion(self, otherVersion, otherExt):
		print("gotVersion(): %s, %s, %s" % (self, otherVersion, otherExt))
		return {"conchTest": "ext data"}

	def realPath(self, path):
		realpath = os.path.abspath("/" + path.lstrip("/"))
		print(">> realpath called for", path, "==>", realpath, file=sys.stderr)
		return realpath

	def _fixPath(self, path):
		abspath = os.path.abspath("/" + path).lstrip("/")

		result = os.path.join(self.chroot, abspath)
		# ensure that path is in chroot
		chrootfix = False
		if not result.startswith(self.chroot):
			chrootfix = True
			result = self.chroot

		print("fixPath: %s ==(%s)==> %s%s" % (path, self.chroot, result, " (chroot fix)" if chrootfix else ""))

		return result

	def getAttrs(self, path, followLinks):
		func = os.stat if followLinks else os.lstat
		
		return self._statToAttrs(func(self._fixPath(path)))

	def openDirectory(self, path):
		realpath = self._fixPath(path)
		print(" >> openDirectory", path, "==>", realpath, file=sys.stderr)
		return SFTPDirectory(realpath)

	def makeDirectory(self, path, attrs):
		realpath = self._fixPath(path)
		print(" >> makeDirectory", path, attrs, realpath, file=sys.stderr)
		os.mkdir(realpath)
		self._setAttrs(path, attrs)

	def setAttrs(self, path, attrs):
		print("Calling setattr for", path, "with", attrs)
		if self._fixPath(path) == self.chroot:
			raise ValueError("No changing the attrs of the /")
		self._setAttrs(path, attrs)

	def _setAttrs(self, path, attrs):
		realpath = self._fixPath(path)

		if "permissions" in attrs:
			# TODO: User specified umask?
			os.chmod(realpath, attrs["permissions"] & 0777)

	def openFile(self, filename, flags, attrs):
		print(" >> openFile", filename, flags, attrs, file=sys.stderr)

		return SFTPFile(self, self._fixPath(filename), flags, attrs, allowWrite=self.allowWrite)
		raise ValueError("maunz")

	def removeFile(self, filename):
		print(" >> removeFile", filename, file=sys.stderr)
		if self.allowWrite:
			realpath = self._fixPath(filename)
			os.unlink(realpath)
		else:
			raise ValueError("Writing is not allowed")

	def renameFile(self, oldpath, newpath):
		print(" >> renameFile '%s' to '%s'" % (oldpath, newpath), file=sys.stderr)
		if self.allowWrite:
			realoldpath = self._fixPath(oldpath)
			realnewpath = self._fixPath(newpath)
			os.rename(realoldpath, realnewpath)
		else:
			raise ValueError("Writing is not allowed")

	def removeDirectory(self, path):
		print(" >> removeDirectory", path, file=sys.stderr)
		if self.allowWrite:
			realpath = self._fixPath(path)
			os.rmdir(realpath)
		else:
			raise ValueError("Writing is not allowed")

	def makeLink(self, linkPath, targetPath):
		print(" >> makeLink %s --> %s" % (linkPath, targetPath), file=sys.stderr)
		if self.allowWrite:
			realLinkPath = self._fixPath(linkPath)
			realTargetPath = self._fixPath(targetPath)
			# TODO: Check if path is inside chroot. if so, do not fix to absolute path, leave it relative
			print(" -- !! real link %s --> %s" % (realLinkPath, realTargetPath))
			os.symlink(realLinkPath, realTargetPath)
		else:
			raise ValueError("Writing is not allowed")

	def readLink(self, path):
		realpath = self._fixPath(path)
		targetPath = os.readlink(realpath)

		# TODO: Make link relative to chroot, if relative link is absolute?
		print(" >> readlink %s --> %s" % (path, targetPath), file=sys.stderr)
		return targetPath
components.registerAdapter(LimitedSFTPServer, LimitedSFTPAvatar, filetransfer.ISFTPServer)

class SFTPDirectory:
	def __init__(self, path):
		self.path = path
		self.files = os.listdir(self.path)

	def __iter__(self):
		return self

	def next(self):
		if len(self.files) > 0:
			fname = self.files.pop(0)
			fstat = os.lstat(os.path.join(self.path, fname))
			longname = lsLine(fname, fstat)
			attrs = LimitedSFTPServer._statToAttrs(fstat)
			
			return (fname, longname, attrs)
		else:
			raise StopIteration

	def close(self):
		self.files = []


class SFTPFile:
	implements(conchinterfaces.ISFTPFile)

	def __init__(self, server, filename, flags, attrs, allowWrite=False):
		print(" >> SFTPFile: open %s with flags %s and attrs %s" % (filename, flags, attrs), file=sys.stderr)
		self.server = server
		self.allowWrite = allowWrite
		self.filename = filename
		openFlags = 0
		mode = 0777

		if flags & FXF_WRITE == FXF_WRITE:
			if allowWrite:
				if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == FXF_READ:
					openFlags = os.O_RDWR
				else:
					openFlags = os.O_WRONLY

				if flags & FXF_APPEND == FXF_APPEND:
					openFlags |= os.O_APPEND
				if flags & FXF_CREAT == FXF_CREAT:
					openFlags |= os.O_CREAT
				if flags & FXF_TRUNC == FXF_TRUNC:
					openFlags |= os.O_TRUNC
				if flags & FXF_EXCL == FXF_EXCL:
					 openFlags |= os.O_EXCL
			else:
				raise ValueError("Write not allowed")
		elif flags & FXF_READ == FXF_READ:
			# ignore all other options, readonly
			openFlags = os.O_RDONLY
		else:
			# unknown mode
			raise ValueError("Unknown permission flags '%s'" % flags)

		if "permissions" in attrs:
			mode = attrs["permissions"]
			del(attrs["permissions"])
		else:
			mode = 0777

		self.fd = os.open(filename, openFlags, mode)
		if attrs:
			self.server._setAttrs(filename, attrs)

	def close(self):
		os.close(self.fd)

	def readChunk(self, offset, length):
		os.lseek(self.fd, offset, os.SEEK_SET)
		return os.read(self.fd, length)

	def writeChunk(self, offset, data):
		if self.allowWrite:
			os.lseek(self.fd, offset, os.SEEK_SET)
			return os.write(self.fd, data)
		else:
			raise ValueError("SFTPFile %s is read only!" % (self.filename))

	def getAttrs(self):
		stat = os.fstat(self.fd)
		return LimitedSFTPServer._statToAttrs(stat)

	def setAttrs(self, attrs):
		raise NotImplementedError()


class SFTPRealm(object):
	implements(portal.IRealm)

	def __init__(self, chroot):
		self.chroot = chroot

	def requestAvatar(self, avatarId, mind, *interfaces):
		print("Requesting avatar", avatarId, mind, interfaces)
		if conchinterfaces.IConchUser in interfaces:
			return interfaces[0], LimitedSFTPAvatar(self.chroot), lambda: self.reportConnClosed(avatarId)

	def reportConnClosed(self, username):
		print("User %s closed the connection" % (username,))


class NoneAuthorization:
	""" NoneAuthorization - "Passwordless" authorization

	We use IPluggableAuthenticationModules as interface so ssh sends keyboard-interactive
	as authentication method. Then we can instantly send an "okay" back. Another option
	would be to patch a null-auth into ssh.
	"""
	implements(checkers.ICredentialsChecker)
	credentialInterfaces = (cred.credentials.IPluggableAuthenticationModules,)

	def requestAvatarId(self, credentials):
		return defer.succeed(str(credentials.username))


def runSFTPServer():
	# fire up ssh server
	realm = SFTPRealm("/maunz")

	sshFactory = factory.SSHFactory()
	sshFactory.portal = portal.Portal(realm)

	# crypto keys
	privateKey = Key.fromString(data=open("id_rsa").read())
	sshFactory.publicKeys  = {'ssh-rsa': privateKey.public()}
	sshFactory.privateKeys = {'ssh-rsa': privateKey}

	# user access
	sshFactory.portal.registerChecker(NoneAuthorization())
	sshFactory.portal.registerChecker(conchcheckers.SSHPublicKeyDatabase())
	users = {'seba': 'maunz'}
	sshFactory.portal.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))


	from twisted.internet import reactor
	reactor.listenTCP(2222, sshFactory)
	reactor.run()

def _parser():
	parser = argparse.ArgumentParser(description="Serve a directory via SFTP")
	# TODO: Argument groups?

	parser.add_argument("target", type=str, help="Directory to serve")
	parser.add_argument("-p", "--port", default=2222, type=int, help="Port to run the sftp server on (Default: 2222)")

	# filesystem stuff
	parser.add_argument("-w", "--writable", default=False, action="store_true", help="Allow write operations (creating/changing/renaming/deleting files and directories)")
	parser.add_argument("--co", "--create-only", default=False, action="store_true", help="Only allow creation of files and directory, but no modification/deletion. Used with -w")
	parser.add_argument("--ns", "--no-symlinks", default=False, action="store_true", help="Disallow creation of symlinks (Note: symlinks outside of the given directory are not allowed)")
	parser.add_argument("--fe", "--follow-external", default=False, action="store_true", help="Follow external symlinks (symlinks that point outside of the chroot)")

	# user management/authorization/access
	# TODO: User management, authorization
	#		   allow users to be specified on commandline
	#		   add --allow-all-users
	#		   allow key based auth
	#		   allow password based auth
	#		   allow none-auth
	# TODO: Web-command (aka "download this authorized keys file" or "use this authorized keys command")
	parser.add_argument("-n", "--nullauth", default=False, action="store_true", help="Null-authentication. No authentication will be done, every user/password combination wins!")
	parser.add_argument("-u", "--users", metavar="users", default=None, type=str, help="List of user/password combinations. Format: user1:passs1,user2:pass2,...")
	parser.add_argument("-a", "--authorized-keys", metavar="authorized keys file", default=None, type=str, help="Path to an authorized_keys file filled with ssh publickeys")

	# TODO: Hostkey management
	parser.add_argument("-k", "--hostkey", metavar="hostkey", default=None, type=str, help="Hostkey to use. You only need to specify the private key")

	parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

	return parser


def main():
	parser = _parser()
	args = parser.parse_args()
	print(args)

	if not args.users and not args.nullauth and not args.authorized_keys:
		parser.error("No authorization chosen, please specify one with -n, -a or -u.")

	return 0
	runSFTPServer()

if __name__ == "__main__":
	#from twisted.python import log
	#log.startLogging(sys.stdout)
	main()
