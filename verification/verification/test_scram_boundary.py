"""Protocol-level SCRAM channel-binding acceptance, using the separate local peer."""
import asyncio,importlib.util,sys
from pathlib import Path
import pytest
import asyncpg
spec=importlib.util.spec_from_file_location('pg_wire_peer',Path(__file__).with_name('pg-wire-peer.py'))
peer_module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=peer_module;spec.loader.exec_module(peer_module)
Peer=peer_module.Peer

async def connect(peer,mode='disable',dsn=False,pool=False):
 kwargs={'timeout':4,'ssl':peer.client_context if peer.tls else False}
 credentials=dict(user='local-test-user',password=peer.password.decode(),database='test',host='127.0.0.1',port=peer.port)
 if dsn:kwargs['dsn']='postgresql://local-test-user:local-test-password@127.0.0.1:'+str(peer.port)+'/test?channel_binding='+mode
 else:kwargs.update(credentials,channel_binding=mode)
 if pool:
  p=await asyncpg.create_pool(**kwargs,min_size=1,max_size=1)
  p.terminate();return
 c=await asyncpg.connect(**kwargs);await c.close()

@pytest.mark.parametrize('mode,tls,mechanisms,expected,gs2',[
 ('disable',True,(b'SCRAM-SHA-256-PLUS',b'SCRAM-SHA-256'),b'SCRAM-SHA-256','n,,'),
 ('prefer',True,(b'SCRAM-SHA-256-PLUS',b'SCRAM-SHA-256'),b'SCRAM-SHA-256-PLUS','p=tls-server-end-point,,'),
 ('require',True,(b'SCRAM-SHA-256-PLUS',),b'SCRAM-SHA-256-PLUS','p=tls-server-end-point,,'),
 ('prefer',True,(b'SCRAM-SHA-256',),b'SCRAM-SHA-256','y,,'),
 ('prefer',False,(b'SCRAM-SHA-256',),b'SCRAM-SHA-256','n,,'),
 ('disable',False,(b'SCRAM-SHA-256',),b'SCRAM-SHA-256','n,,')])
def test_negotiation_and_exact_proof(mode,tls,mechanisms,expected,gs2):
 async def scenario():
  async with Peer(tls=tls,mechanisms=mechanisms).serve() as p:
   await connect(p,mode);await asyncio.sleep(.03)
   assert not p.errors and p.sessions[0]['authenticated']
   assert p.sessions[0]['mechanism']==expected and p.sessions[0]['first'].startswith(gs2)
 asyncio.run(scenario())

@pytest.mark.parametrize('tls,mechanisms',[(False,(b'SCRAM-SHA-256',)),(True,(b'SCRAM-SHA-256',))])
def test_require_rejects_downgrade(tls,mechanisms):
 async def scenario():
  async with Peer(tls=tls,mechanisms=mechanisms).serve() as p:
   try:await connect(p,'require')
   except (ValueError,asyncpg.InterfaceError,asyncpg.PostgresError):pass
   else:raise AssertionError('channel_binding=require accepted downgrade')
   assert all(not s.get('authenticated') for s in p.sessions)
 asyncio.run(scenario())

def test_invalid_server_signature_rejected():
 async def scenario():
  async with Peer(bad_server_signature=True).serve() as p:
   with pytest.raises((asyncpg.InterfaceError,asyncpg.PostgresError)):await connect(p,'require')
 asyncio.run(scenario())

def test_omitted_server_signature_cannot_complete_authentication():
 async def scenario():
  async with Peer(omit_server_signature=True).serve() as p:
   with pytest.raises((asyncpg.InterfaceError,asyncpg.PostgresError,TimeoutError)):await connect(p,'require')
 asyncio.run(scenario())

def test_missing_binding_data_requires_refusal_and_no_cross_call_cache(monkeypatch):
 from asyncpg import _channel_binding as cb
 async def scenario():
  async with Peer().serve() as p:
   original=cb._get_peer_certificate_der;calls=[]
   def unavailable(ssl_object):calls.append(ssl_object);return None
   with monkeypatch.context() as patcher:
    patcher.setattr(cb,'_get_peer_certificate_der',unavailable)
    with pytest.raises((asyncpg.InterfaceError,asyncpg.PostgresError)):await connect(p,'require')
   assert calls
   await connect(p,'require');await asyncio.sleep(.03)
   assert not p.errors and p.sessions[-1]['mechanism']==b'SCRAM-SHA-256-PLUS'
 asyncio.run(scenario())

def test_independent_certificates_concurrent_connections():
 async def scenario():
  async with Peer().serve() as left,Peer().serve() as right:
   assert left.binding!=right.binding
   await asyncio.gather(connect(left,'require'),connect(right,'require'))
   await asyncio.sleep(.03)
   assert not left.errors and not right.errors
   assert left.sessions[0]['binding_hex']!=right.sessions[0]['binding_hex']
 asyncio.run(scenario())

@pytest.mark.parametrize('dsn,pool',[(True,False),(False,True),(True,True)])
def test_connection_routes_preserve_requirement(dsn,pool):
 async def scenario():
  async with Peer().serve() as p:
   await connect(p,'require',dsn=dsn,pool=pool);await asyncio.sleep(.03)
   assert not p.errors and p.sessions[0]['mechanism']==b'SCRAM-SHA-256-PLUS'
 asyncio.run(scenario())

def test_invalid_mode_rejected_before_network():
 async def scenario():
  with pytest.raises((ValueError,asyncpg.InterfaceError)):
   await asyncpg.connect(host='127.0.0.1',port=1,channel_binding='required',timeout=1)
 asyncio.run(scenario())
