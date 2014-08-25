#!/usr/bin/env python2
from __future__ import print_function

__version__ = "0.1"

import argparse
import os
import sys
import re

from Crypto.PublicKey import RSA

from twisted import cred, internet
from twisted.internet import reactor
from twisted.python import components, filepath
from twisted.cred import portal, checkers
from twisted.conch import avatar, interfaces as conchinterfaces, checkers as conchcheckers
from twisted.conch.ls import lsLine
from twisted.conch.ssh import filetransfer, session, factory, keys
from twisted.conch.ssh.filetransfer import SFTPError, FX_PERMISSION_DENIED, FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
from zope.interface import implements

# TODO:
#	cleanup
#		pathkram geradeziehen

class SSHUnavailableProtocol(internet.protocol.Protocol):
	def connectionMade(self):
		self.transport.write("This SSH server runs SFTP only!\r\n")

	def dataReceived(self, bytes):
		pass

	def connectionLost(self, reason):
		pass

class ChrootSpecs(object):
	def __init__(self, directory, allowWrite, createOnly, noSymlinks, followExternalSymlinks):
		self.directory = self._fixDir(directory)
		self.allowWrite = allowWrite
		self.createOnly = createOnly
		self.noSymlinks = noSymlinks
		self.followExternalSymlinks = followExternalSymlinks

	def _fixDir(self, directory):
		return os.path.join(os.getcwd(), directory)


class LimitedSFTPAvatar(avatar.ConchUser):
	implements(conchinterfaces.ISession)

	def __init__(self, chroot):
		print("Init SFTPAvatar (%s)" % (self))
		avatar.ConchUser.__init__(self)

		self.chroot = chroot
		self.channelLookup['session'] = session.SSHSession
		self.subsystemLookup['sftp'] = filetransfer.FileTransferServer

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

	def __init__(self, avatar):
		self.avatar = avatar
		self.chrootSpecs = avatar.chroot

		# get chroot path without symlink
		self.chroot = os.path.realpath(self.chrootSpecs.directory).rstrip("/") + "/"
		self.chrootRe = re.compile("^%s(/.*)?$" % re.escape(self.chroot.rstrip("/")))

		print("Initialized LimitedSFTPServer() for directory", self.chroot)

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
		if not self.chrootRe.match(result):
			print(" !! CHROOT: Link is not inside chroot, whyever (chroot: %s, old: %s, joined: %s)" % (self.chroot, abspath, result))
			chrootfix = True
			result = self.chroot
			raise SFTPError(FX_PERMISSION_DENIED, "CHROOT: Link is not inside chroot, whyever (chroot: %s, old: %s, joined: %s)" % (self.chroot, abspath, result))

		# check if path is a symlink and is outside
		realpath = os.path.realpath(result)
		print("Realpath", realpath)
		if not self.chrootRe.match(realpath) and not self.chrootSpecs.followExternalSymlinks:
			print("CHROOT: Link is not inside chroot and following symlinks outside chroot is forbidden (path: %s, realpath: %s)" % (result, realpath))
			raise SFTPError(FX_PERMISSION_DENIED, "CHROOT: Link is not inside chroot and following symlinks outside chroot is forbidden (path: %s, realpath: %s)" % (result, realpath))

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
		if not self.chrootSpecs.allowWrite or self.chrootSpecs.createOnly:
			raise SFTPError(FX_PERMISSION_DENIED, "Directory creation not allowed (path: %s)" % path)
		os.mkdir(realpath)
		self._setAttrs(path, attrs)

	def setAttrs(self, path, attrs):
		print(" >> setAttrs", path, attrs, file=sys.stderr)
		if self._fixPath(path) == self.chroot:
			raise SFTPError(FX_PERMISSION_DENIED, "Calling setAttr on root directory is not allowed")
		if not self.chrootSpecs.allowWrite or self.chrootSpecs.createOnly:
			raise SFTPError(FX_PERMISSION_DENIED, "Mode-changing not allowed")
		self._setAttrs(path, attrs)

	def _setAttrs(self, path, attrs):
		realpath = self._fixPath(path)

		if "permissions" in attrs:
			os.chmod(realpath, attrs["permissions"] & 0777)

	def openFile(self, filename, flags, attrs):
		print(" >> openFile", filename, flags, attrs, file=sys.stderr)

		return SFTPFile(self, self._fixPath(filename), flags, attrs, allowWrite=self.chrootSpecs.allowWrite)

	def removeFile(self, filename):
		print(" >> removeFile", filename, file=sys.stderr)
		if self.chrootSpecs.allowWrite:
			realpath = self._fixPath(filename)
			os.unlink(realpath)
		else:
			raise SFTPError(FX_PERMISSION_DENIED, "Writing is not allowed")

	def renameFile(self, oldpath, newpath):
		print(" >> renameFile '%s' to '%s'" % (oldpath, newpath), file=sys.stderr)
		if self.chrootSpecs.allowWrite:
			if self.chrootSpecs.createOnly:
				raise SFTPError(FX_PERMISSION_DENIED, "In create-only mode, no renaming allowed")
			realoldpath = self._fixPath(oldpath)
			realnewpath = self._fixPath(newpath)
			os.rename(realoldpath, realnewpath)
		else:
			raise SFTPError(FX_PERMISSION_DENIED, "Writing (and therefore renaming) is not allowed")

	def removeDirectory(self, path):
		print(" >> removeDirectory", path, file=sys.stderr)
		if self.chrootSpecs.allowWrite:
			if self.chrootSpecs.createOnly:
				raise SFTPError(FX_PERMISSION_DENIED, "In create-only mode, deleting directories is not allowed")
			realpath = self._fixPath(path)
			os.rmdir(realpath)
		else:
			raise SFTPError(FX_PERMISSION_DENIED, "Writing (and therefore deleting directories) is not allowed")

	def makeLink(self, linkPath, targetPath):
		print(" >> makeLink %s --> %s" % (linkPath, targetPath), file=sys.stderr)
		if self.chrootSpecs.allowWrite:
			realLinkPath = self._fixPath(linkPath)
			realTargetPath = self._fixPath(targetPath)
			# TODO: Check if path is inside chroot. if so, do not fix to absolute path, leave it relative
			print(" -- !! real link %s --> %s" % (realLinkPath, realTargetPath))

			if self.chrootSpecs.noSymlinks:
				raise SFTPError(FX_PERMISSION_DENIED, "Symlink creation are not allowed")
			if self.chrootSpecs.createOnly and os.path.exists(realLinkPath):
				raise SFTPError(FX_PERMISSION_DENIED, "File already exists (create-only mode)")
			os.symlink(realLinkPath, realTargetPath)
		else:
			raise SFTPError(FX_PERMISSION_DENIED, "Writing is not allowed")

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
			if self.server.chrootSpecs.allowWrite:
				if self.server.chrootSpecs.createOnly and os.path.exists(filename):
					raise SFTPError(FX_PERMISSION_DENIED, "File already exists")
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
				raise SFTPError(FX_PERMISSION_DENIED, "Write not allowed")
		elif flags & FXF_READ == FXF_READ:
			# ignore all other options, readonly
			openFlags = os.O_RDONLY
		else:
			# unknown mode
			raise SFTPError(FX_PERMISSION_DENIED, "Unknown permission flags '%s'" % flags)

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
		if self.server.chrootSpecs.allowWrite:
			os.lseek(self.fd, offset, os.SEEK_SET)
			return os.write(self.fd, data)
		else:
			raise SFTPError(FX_PERMISSION_DENIED, "SFTPFile %s is read only!" % (self.filename))

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
	as authentication method. Then we can instantly send an "okay" back. Newer versions
	of twisted-conch also support none-authentication (see [0]). For this to work this
	class also implements the IAnonymous credential interface.

	[0] http://twistedmatrix.com/users/diffresource.twistd/5531
	"""
	implements(checkers.ICredentialsChecker)
	credentialInterfaces = (cred.credentials.IPluggableAuthenticationModules, cred.credentials.IAnonymous,)

	def requestAvatarId(self, credentials):
		return internet.defer.succeed(str(credentials.username))


class SSHAuthorizedKeysFile(conchcheckers.SSHPublicKeyDatabase):
	def __init__(self, files):
		self.files = files

	def getAuthorizedKeysFiles(self, credentials):
		return [filepath.FilePath(f) for f in self.files]


def runSFTPServer():
	# fire up ssh server
	realm = SFTPRealm("/maunz")

	sshFactory = factory.SSHFactory()
	sshFactory.portal = portal.Portal(realm)

	# crypto keys
	privateKey = keys.Key.fromString(data=open("id_rsa").read())
	sshFactory.publicKeys  = {'ssh-rsa': privateKey.public()}
	sshFactory.privateKeys = {'ssh-rsa': privateKey}

	# user access
	sshFactory.portal.registerChecker(NoneAuthorization())
	sshFactory.portal.registerChecker(conchcheckers.SSHPublicKeyDatabase())
	users = {'seba': 'maunz'}
	sshFactory.portal.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))


	reactor.listenTCP(2222, sshFactory)
	reactor.run()

def _parser():
	parser = argparse.ArgumentParser(description="Serve a directory via SFTP")
	# TODO: Argument groups?

	parser.add_argument("target", type=str, help="Directory to serve")
	parser.add_argument("-p", "--port", default=2222, type=int, help="Port to run the sftp server on (Default: 2222)")
	parser.add_argument("-d", "--debug", default=False, action="store_true", help="Enable twisted's debug facilities")

	# filesystem stuff
	parser.add_argument("-w", "--writable", default=False, action="store_true", help="Allow write operations (creating/changing/renaming/deleting files and directories)")
	parser.add_argument("--co", "--create-only", default=False, action="store_true", help="Only allow creation of files and directory, but no modification/deletion. Used with -w")
	parser.add_argument("--ns", "--no-symlinks", default=False, action="store_true", help="Disallow creation of symlinks (Note: symlinks outside of the given directory are not allowed)")
	parser.add_argument("--fe", "--follow-external", default=False, action="store_true", help="Follow external symlinks (symlinks that point outside of the chroot)")

	# user management/authorization/access
	# TODO: Web-command (aka "download this authorized keys file" or "use this authorized keys command")
	parser.add_argument("-n", "--nullauth", default=False, action="store_true", help="Null-authentication. No authentication will be done, every user/password combination wins!")
	parser.add_argument("-u", "--users", metavar="users", default=None, type=str, help="List of user/password combinations. Format: user1:passs1,user2:pass2,...")
	parser.add_argument("-a", "--authorized-keys", metavar="authorized keys file", default=None, type=str, help="Path to an authorized_keys file filled with ssh publickeys")

	# Hostkey management
	parser.add_argument("-k", "--hostkey", metavar="hostkey", default=None, type=str, help="Hostkey to use. You only need to specify the private key")

	parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

	return parser


def main():
	parser = _parser()
	args = parser.parse_args()

	if not args.users and not args.nullauth and not args.authorized_keys:
		parser.error("No authorization chosen, please specify one with -n, -a or -u.")

	# fire up ssh server
	targetWasCreated = False
	if not os.path.exists(args.target):
		if not args.writable:
			print("Warning: You specified a non-existing target but didn't allow it to be writable.")
			print("         You will basically serve an empty directory (which I will create for you.")
		print("Creating target directory")
		os.mkdir(args.target)
		targetWasCreated = True
	elif not os.path.isdir(args.target):
		parser.error("Target needs to be a directory")

	chroot = ChrootSpecs(args.target, args.writable, args.co, args.ns, args.fe)

	realm = SFTPRealm(chroot)

	sshFactory = factory.SSHFactory()
	sshFactory.portal = portal.Portal(realm)

	# hostkey handling
	privateKey = None

	try:
		if args.hostkey:
			privateKey = keys.Key.fromString(data=open(args.hostkey).read())
		else:
			confPath = os.path.expanduser("~/.servesftp/")
			keyPath = os.path.join(confPath, "hostkey")
			if os.path.exists(keyPath):
				# load key from user's home
				privateKey = keys.Key.fromString(data=open(keyPath).read())
			else:
				bits = 2048
				print("Generating %sbit RSA hostkey..." % bits)
				rsaKey = RSA.generate(bits)
				privateKey = keys.Key.fromString(data=rsaKey.exportKey("PEM"))

				try:
					if not os.path.exists(confPath):
						os.mkdir(confPath)
					keyFile = open(keyPath, "w")
					keyFile.write(rsaKey.exportKey("PEM") + "\n")
					keyFile.close()
				except (OSError, IOError) as e:
					print("Warning: Could not save private key to %s: %s" % (keyPath, e))
	except IOError as e:
		print("Error: Could not open private hostkey: %s" % (e,))
		privateKey = None
	except keys.BadKeyError:
		print("Error: The specified key is not in an understandable format!")
		privateKey = None

	if not privateKey:
		print("No feasible hostkey could be found")
		sys.exit(1)

	if privateKey.isPublic():
		print("You specified a public key as hostkey but a private one is needed.")
		sys.exit(1)

	sshFactory.publicKeys  = {'ssh-rsa': privateKey.public()}
	sshFactory.privateKeys = {'ssh-rsa': privateKey}

	# user access
	if args.nullauth:
		sshFactory.portal.registerChecker(NoneAuthorization())

	if args.authorized_keys:
		sshFactory.portal.registerChecker(SSHAuthorizedKeysFile([args.authorized_keys]))

	if args.users:
		users = args.users.split(",")
		userdb = {}
		error = False
		for i, user in enumerate(users, 1):
			if ":" not in user:
				print("Error: User number %d (%s) is missing a password!" % (i, user), file=sys.stderr)
				error = True
			else:
				user, password = user.split(":")
				if len(user) <= 0:
					print("Error: User number %d has an empty username" % (i,), file=sys.stderr)
					error = True
				elif len(password) <= 0:
					print("Error: User number %d (%s) has an empty password" % (i, user), file=sys.stderr)
					error = True
				else:
					userdb[user] = password

		if error:
			sys.exit(1)
		
		# I actually don't care if they name their class "DontUse". It perfectly fits the need
		# of a in-memory store for invaluable throw-away passwords.
		sshFactory.portal.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(**userdb))

	if args.debug:
		from twisted.python import log
		log.startLogging(sys.stdout)

	try:
		reactor.listenTCP(args.port, sshFactory)
	except internet.error.CannotListenError as e:
		print("Error binding to port: %s" % (e,))
		sys.exit(1)

	# run the thing!
	reactor.run()

	# cleanup
	if targetWasCreated:
		# try to delete directory, if was left empty
		try:
			os.rmdir(args.target)
		except OSError:
			pass
	print("Good bye")

if __name__ == "__main__":
	main()
