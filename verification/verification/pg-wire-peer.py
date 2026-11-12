"""Offline PostgreSQL/SCRAM test peer. Cryptographic proof checks are independent of asyncpg."""
import asyncio,base64,hashlib,hmac,ssl,struct
from contextlib import asynccontextmanager,suppress
from dataclasses import dataclass,field
from cryptography.hazmat.primitives import hashes,serialization
import trustme

def packet(tag,payload):return tag+struct.pack('!I',len(payload)+4)+payload
def authentication(code,payload=b''):return packet(b'R',struct.pack('!I',code)+payload)
def fields(message):return dict(x.split(b'=',1) for x in message.split(b','))
def xor(left,right):return bytes(a^b for a,b in zip(left,right))

@dataclass
class Peer:
 tls:bool=True
 mechanisms:tuple=(b'SCRAM-SHA-256-PLUS',b'SCRAM-SHA-256')
 bad_server_signature:bool=False
 omit_server_signature:bool=False
 password:bytes=b'local-test-password'
 sessions:list=field(default_factory=list)
 errors:list=field(default_factory=list)
 tasks:set=field(default_factory=set)

 def configure(self):
  self.ca=trustme.CA();self.cert=self.ca.issue_cert('localhost','127.0.0.1')
  self.server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.cert.configure_cert(self.server_context)
  self.client_context=ssl.create_default_context();self.ca.configure_trust(self.client_context)
  from cryptography import x509
  certificate=x509.load_pem_x509_certificate(self.cert.cert_chain_pems[0].bytes())
  self.binding=hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).digest()

 async def read_message(self,reader):
  tag=await reader.readexactly(1);size=struct.unpack('!I',await reader.readexactly(4))[0]
  assert 4<=size<=100000
  return tag,await reader.readexactly(size-4)

 async def client(self,reader,writer):
  task=asyncio.current_task();self.tasks.add(task);session={'authenticated':False};self.sessions.append(session)
  try:
   length=struct.unpack('!I',await reader.readexactly(4))[0]
   startup=await reader.readexactly(length-4)
   if length==8 and startup==struct.pack('!I',80877103):
    writer.write(b'S' if self.tls else b'N');await writer.drain()
    if self.tls:await writer.start_tls(self.server_context,ssl_handshake_timeout=3)
    length=struct.unpack('!I',await reader.readexactly(4))[0];startup=await reader.readexactly(length-4)
   session['tls']=writer.get_extra_info('ssl_object') is not None
   assert startup[:4]==struct.pack('!I',196608)
   writer.write(authentication(10,b'\0'.join(self.mechanisms)+b'\0\0'));await writer.drain()
   tag,initial=await self.read_message(reader);assert tag==b'p'
   mechanism,_,rest=initial.partition(b'\0');size=struct.unpack('!I',rest[:4])[0];first=rest[4:]
   assert len(first)==size
   session['mechanism']=mechanism;session['first']=first.decode()
   header_parts=first.split(b',',2);header=b','.join(header_parts[:2])+b',';bare=header_parts[2]
   nonce=fields(bare)[b'r'];server_nonce=nonce+b'local-peer-nonce';salt=b'local-peer-salt'
   server_first=b'r='+server_nonce+b',s='+base64.b64encode(salt)+b',i=4096'
   writer.write(authentication(11,server_first));await writer.drain()
   tag,final=await self.read_message(reader);assert tag==b'p';attrs=fields(final)
   session['binding_hex']=base64.b64decode(attrs[b'c']).hex()
   assert attrs[b'r']==server_nonce
   if mechanism==b'SCRAM-SHA-256-PLUS':
    assert session['tls'] and header==b'p=tls-server-end-point,,'
    assert base64.b64decode(attrs[b'c'])==header+self.binding
   else:assert base64.b64decode(attrs[b'c'])==header
   salted=hashlib.pbkdf2_hmac('sha256',self.password,salt,4096)
   auth_message=bare+b','+server_first+b','+final.rsplit(b',p=',1)[0]
   client_key=hmac.digest(salted,b'Client Key','sha256');stored=hashlib.sha256(client_key).digest()
   assert hmac.compare_digest(base64.b64decode(attrs[b'p']),xor(client_key,hmac.digest(stored,auth_message,'sha256')))
   server_key=hmac.digest(salted,b'Server Key','sha256');signature=hmac.digest(server_key,auth_message,'sha256')
   if self.bad_server_signature:signature=bytes([signature[0]^1])+signature[1:]
   if not self.omit_server_signature:writer.write(authentication(12,b'v='+base64.b64encode(signature)))
   writer.write(authentication(0))
   for name,value in [(b'server_version',b'16.0'),(b'client_encoding',b'UTF8'),(b'integer_datetimes',b'on')]:writer.write(packet(b'S',name+b'\0'+value+b'\0'))
   writer.write(packet(b'K',struct.pack('!II',12345,6789)));writer.write(packet(b'Z',b'I'));await writer.drain()
   session['authenticated']=True
   while True:
    tag,data=await self.read_message(reader)
    if tag==b'X':break
    raise AssertionError('Unexpected post-authentication command: '+repr(tag))
  except (asyncio.IncompleteReadError,ConnectionResetError,BrokenPipeError):pass
  except Exception as error:self.errors.append(type(error).__name__+': '+str(error))
  finally:
   writer.close()
   with suppress(Exception):await writer.wait_closed()
   self.tasks.discard(task)

 @asynccontextmanager
 async def serve(self):
  self.configure();listener=await asyncio.start_server(self.client,'127.0.0.1',0)
  self.port=listener.sockets[0].getsockname()[1]
  try:yield self
  finally:
   listener.close();await listener.wait_closed()
   for task in list(self.tasks):task.cancel()
   await asyncio.gather(*list(self.tasks),return_exceptions=True)

if __name__=='__main__':
 import asyncpg
 async def control():
  for tls in (False,True):
   async with Peer(tls=tls,mechanisms=(b'SCRAM-SHA-256',)).serve() as peer:
    connection=await asyncpg.connect(host='127.0.0.1',port=peer.port,user='local-test-user',password=peer.password.decode(),database='test',ssl=peer.client_context if tls else False,timeout=3)
    await connection.close();await asyncio.sleep(.02)
    assert not peer.errors and peer.sessions[0]['authenticated']
    print('PASS original asyncpg authenticates against independently checked SCRAM wire peer; TLS=',tls)
 asyncio.run(control())
