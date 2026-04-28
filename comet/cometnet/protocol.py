"""
CometNet Protocol Module

Defines all message types and serialization logic for CometNet P2P communication.
Uses MsgPack for efficient binary serialization via msgspec.
"""

import time
from enum import Enum
from typing import ClassVar, List, Optional, Union

import msgspec
import msgspec.msgpack
from msgspec import UNSET, UnsetType

from comet.utils.formatting import normalize_info_hash

# Protocol version for backwards compatibility
PROTOCOL_VERSION = "1.0"

# Encoder used by both to_signable_bytes (excludes signature via UNSET)
# and anywhere we need canonical/deterministic msgpack encoding.
# order='sorted' sorts all map keys alphabetically at every nesting level.
_CANONICAL_ENCODER = msgspec.msgpack.Encoder(order="sorted")


class MessageType(str, Enum):
    """Types of messages in the CometNet protocol."""

    # Core messages
    HANDSHAKE = "handshake"
    PING = "ping"
    PONG = "pong"
    PEER_REQUEST = "peer_request"
    PEER_RESPONSE = "peer_response"
    TORRENT_ANNOUNCE = "torrent_announce"
    TORRENT_QUERY = "torrent_query"
    TORRENT_RESPONSE = "torrent_response"
    SYNC_REQUEST = "sync_request"
    SYNC_RESPONSE = "sync_response"

    # Pool management
    POOL_MANIFEST = "pool_manifest"
    POOL_JOIN_REQUEST = "pool_join"
    POOL_MEMBER_UPDATE = "pool_member_update"
    POOL_DELETE = "pool_delete"


class BaseMessage(msgspec.Struct):
    """Base class for all CometNet messages."""

    MESSAGE_TYPE: ClassVar[MessageType]

    # Union[str, int] for backwards compatibility: old nodes incorrectly reused
    # this field for the pool manifest revision number (an int), shadowing the
    # protocol version string. PoolManifestMessage.__post_init__ migrates that
    # integer into manifest_version so the value is not lost.
    # TODO: revert to `str` once all nodes are on new code.
    version: Union[str, int] = PROTOCOL_VERSION
    timestamp: float = msgspec.field(default_factory=time.time)
    sender_id: str = ""  # Node ID of the sender
    # Union with UnsetType so to_signable_bytes can replace it with UNSET to
    # omit the field from the canonical bytes without touching the wire format.
    signature: Union[str, UnsetType] = ""  # Hex-encoded signature

    @property
    def type(self) -> MessageType:
        return self.MESSAGE_TYPE

    def to_signable_bytes(self) -> bytes:
        """
        Returns the bytes that should be signed.
        Excludes the signature field itself.
        Uses MsgPack with sorted keys for stable canonicalization.
        """
        copy = msgspec.structs.replace(self, signature=UNSET)
        return _CANONICAL_ENCODER.encode(copy)

    def to_bytes(self) -> bytes:
        return msgspec.msgpack.encode(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BaseMessage":
        return msgspec.msgpack.decode(data, type=cls)


class HandshakeMessage(
    BaseMessage, tag_field="type", tag=MessageType.HANDSHAKE.value
):
    """
    Initial handshake message sent when connecting to a peer.

    Contains the sender's public key for identity verification
    and future encrypted communications.
    """

    MESSAGE_TYPE = MessageType.HANDSHAKE
    public_key: str = ""  # Hex-encoded public key
    listen_port: int = 0  # Port this node is listening on (for reverse connections)
    public_url: Optional[str] = None  # Full public URL (for reverse proxies)
    alias: Optional[str] = None  # Friendly name for the node
    capabilities: List[str] = msgspec.field(default_factory=list)  # Future extension
    network_token: Optional[str] = None  # HMAC token for private network auth


class PingMessage(BaseMessage, tag_field="type", tag=MessageType.PING.value):
    """Ping message to check if a peer is still alive."""

    MESSAGE_TYPE = MessageType.PING
    nonce: str = ""  # Random nonce for matching pong


class PongMessage(BaseMessage, tag_field="type", tag=MessageType.PONG.value):
    """Pong response to a ping message."""

    MESSAGE_TYPE = MessageType.PONG
    nonce: str = ""  # Echo of the ping nonce


class PeerInfo(msgspec.Struct):
    """Information about a peer for exchange."""

    node_id: str
    address: str  # WebSocket URL (e.g., wss://host:port)
    last_seen: float = 0.0
    reputation: float = 50.0


class PeerRequest(BaseMessage, tag_field="type", tag=MessageType.PEER_REQUEST.value):
    """Request for a list of known peers."""

    MESSAGE_TYPE = MessageType.PEER_REQUEST
    max_peers: int = 20  # Maximum number of peers to return


class PeerResponse(BaseMessage, tag_field="type", tag=MessageType.PEER_RESPONSE.value):
    """Response containing a list of known peers."""

    MESSAGE_TYPE = MessageType.PEER_RESPONSE
    peers: List[PeerInfo] = msgspec.field(default_factory=list)


class TorrentMetadata(msgspec.Struct):
    """
    Metadata for a torrent shared across the network.

    This is the core data structure that CometNet propagates.
    """

    # Required fields first (no defaults)
    info_hash: str  # 40-character hex string
    title: str
    size: int  # Size in bytes
    tracker: str  # Source/tracker name
    imdb_id: str

    # Optional fields
    seeders: Optional[int] = None
    file_index: Optional[int] = None
    season: Optional[int] = None
    episode: Optional[int] = None
    sources: List[str] = msgspec.field(default_factory=list)
    parsed: Optional[dict] = None  # Serialized RTN ParsedData
    updated_at: float = msgspec.field(default_factory=time.time)
    contributor_id: str = ""  # Node ID of the original contributor
    contributor_public_key: str = (
        ""  # Public key of the original contributor (for validation)
    )
    # Union with UnsetType so to_signable_bytes can omit this field without
    # affecting the wire format (signature stays present as "" or hex string).
    contributor_signature: Union[str, UnsetType] = ""
    
    # Pool association
    pool_id: Optional[str] = None  # Pool this torrent belongs to (if any)

    def __post_init__(self):
        # Validate that info_hash is a valid 40-character hex string.
        self.info_hash = normalize_info_hash(self.info_hash)
        if len(self.info_hash) != 40:
            raise ValueError("info_hash must be 40 characters")
        try:
            int(self.info_hash, 16)
        except ValueError:
            raise ValueError("info_hash must be valid hexadecimal")
        
        # Validate that size is a reasonable value.
        if self.size < 0:
            raise ValueError("size must be non-negative")
        if self.size > 10 * 1024**4:  # 10 TB max
            raise ValueError("size exceeds maximum allowed value")
        
        # Require a non-empty media identifier for network torrent metadata.
        if not self.imdb_id:
            raise ValueError("imdb_id is required")

    def to_signable_bytes(self) -> bytes:
        """Returns bytes for signing (excludes contributor_signature)."""
        copy = msgspec.structs.replace(self, contributor_signature=UNSET)
        return _CANONICAL_ENCODER.encode(copy)


class TorrentAnnounce(
    BaseMessage, tag_field="type", tag=MessageType.TORRENT_ANNOUNCE.value
):
    """
    Announce one or more torrents to the network.

    This is the primary gossip message for propagating torrent metadata.
    """

    MESSAGE_TYPE = MessageType.TORRENT_ANNOUNCE
    torrents: List[TorrentMetadata] = msgspec.field(default_factory=list)
    ttl: int = 5  # Time-to-live (hops remaining)
    visited_nodes: List[str] = msgspec.field(
        default_factory=list
    )  # List of nodes that have seen this message
    
    def __post_init__(self):
        # Validate that we don't exceed max torrents per message.
        if len(self.torrents) > 1000:
            raise ValueError("Maximum 1000 torrents per announce message")


class TorrentQuery(
    BaseMessage, tag_field="type", tag=MessageType.TORRENT_QUERY.value
):
    """Query for specific torrents (by info_hash or media ID)."""

    MESSAGE_TYPE = MessageType.TORRENT_QUERY
    info_hashes: List[str] = msgspec.field(default_factory=list)
    imdb_id: Optional[str] = None
    limit: int = 50


class TorrentResponse(
    BaseMessage, tag_field="type", tag=MessageType.TORRENT_RESPONSE.value
):
    """Response to a torrent query."""

    MESSAGE_TYPE = MessageType.TORRENT_RESPONSE
    torrents: List[TorrentMetadata] = msgspec.field(default_factory=list)
    query_id: str = ""  # Reference to the original query


# ==================== Pool Messages ====================


class PoolManifestMessage(
    BaseMessage, tag_field="type", tag=MessageType.POOL_MANIFEST.value
):
    """
    Broadcast or update a pool manifest.

    Used to propagate pool definitions across the network.
    """

    MESSAGE_TYPE = MessageType.POOL_MANIFEST
    pool_id: str = ""
    display_name: str = ""
    description: str = ""
    creator_key: str = ""
    members: List[dict] = msgspec.field(default_factory=list)
    join_mode: str = "invite"
    # Renamed from 'version' to avoid shadowing BaseMessage.version (str).
    # Old nodes encode pool manifest revision as "version" (int); __post_init__
    # migrates that value here so it isn't silently lost.
    manifest_version: int = 1
    created_at: float = 0.0  # Creation timestamp
    updated_at: float = 0.0  # Last update timestamp
    manifest_signatures: dict = msgspec.field(
        default_factory=dict
    )  # admin_key -> sig

    def __post_init__(self):
        if isinstance(self.version, int):
            self.manifest_version = self.version

    # TODO: figure out if this is worth a protocol version bump
    def to_signable_bytes(self) -> bytes:
        copy = msgspec.structs.replace(self, signature=UNSET)
        if not isinstance(self.version, int):
            return _CANONICAL_ENCODER.encode(copy)
        # Old nodes signed without manifest_version (the field didn't exist).
        # Reproduce their canonical bytes by building the map manually.
        d = {}
        for field in msgspec.structs.fields(copy):
            if field.name == "manifest_version":
                continue
            val = getattr(copy, field.name)
            if val is not UNSET:
                d[field.name] = val
        d["type"] = self.MESSAGE_TYPE.value
        return _CANONICAL_ENCODER.encode(d)


class PoolJoinRequest(
    BaseMessage, tag_field="type", tag=MessageType.POOL_JOIN_REQUEST.value
):
    """Request to join a pool."""

    MESSAGE_TYPE = MessageType.POOL_JOIN_REQUEST
    pool_id: str = ""
    invite_code: Optional[str] = None  # For invite-based join

    requester_key: str = ""
    alias: Optional[str] = None  # Friendly name of the requester


class PoolMemberUpdate(
    BaseMessage, tag_field="type", tag=MessageType.POOL_MEMBER_UPDATE.value
):
    """Notify network of membership changes."""

    MESSAGE_TYPE = MessageType.POOL_MEMBER_UPDATE
    pool_id: str = ""
    action: str = ""  # "add", "remove", "promote", "demote", "leave"
    member_key: str = ""
    new_role: Optional[str] = None
    updated_by: str = ""  # Admin who made the change
    manifest_signatures: dict = msgspec.field(
        default_factory=dict
    )  # Signatures of the NEW manifest state


class PoolDeleteMessage(
    BaseMessage, tag_field="type", tag=MessageType.POOL_DELETE.value
):
    """Notify network that a pool has been deleted by its creator."""

    MESSAGE_TYPE = MessageType.POOL_DELETE
    pool_id: str = ""
    deleted_by: str = ""


# Union type for all possible message types
AnyMessage = Union[
    HandshakeMessage,
    PingMessage,
    PongMessage,
    PeerRequest,
    PeerResponse,
    TorrentAnnounce,
    TorrentQuery,
    TorrentResponse,
    PoolManifestMessage,
    PoolJoinRequest,
    PoolMemberUpdate,
    PoolDeleteMessage,
]

# Single tagged union decoder, dispatches via the "type" tag field
_DECODER = msgspec.msgpack.Decoder(AnyMessage)

def parse_message(data: Union[str, bytes]) -> Optional[AnyMessage]:
    """Parse MsgPack bytes into the appropriate message type."""
    if isinstance(data, str):
        # Should not happen, but handle graceful fail
        return None
    try:
        return _DECODER.decode(data)
    except Exception:
        return None
