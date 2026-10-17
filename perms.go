package chriscordbot

// perms.go — what a bot can ask for in its Add to server link. These are
// the server's permission bits (roles.rs). Whoever adds the bot decides,
// and never gives more than they have themselves. A bot never gets
// Administrator or Manage Bots.

const (
	PermSendMessages   uint64 = 1 << 0
	PermAttachFiles    uint64 = 1 << 1
	PermAddReactions   uint64 = 1 << 2
	PermManageMessages uint64 = 1 << 3
	PermConnect        uint64 = 1 << 4
	PermKickMembers    uint64 = 1 << 5
	PermBanMembers     uint64 = 1 << 6
	PermPinMessages    uint64 = 1 << 7
	PermReadHistory    uint64 = 1 << 12
	PermChangeNickname uint64 = 1 << 14
	PermEmbedLinks     uint64 = 1 << 16
	PermSpeak          uint64 = 1 << 17
	PermVideo          uint64 = 1 << 18
	PermMuteMembers    uint64 = 1 << 19
	PermDeafenMembers  uint64 = 1 << 20
	PermMoveMembers    uint64 = 1 << 21
	PermListen         uint64 = 1 << 23
	// PermImportMessages: the Discord importer, without the owner key. Only
	// a server's owner can give it.
	PermImportMessages uint64 = 1 << 25

	// What a bot that chats asks for.
	PermsChat = PermSendMessages | PermAddReactions | PermEmbedLinks | PermReadHistory
	// What a bot that plays sound in calls asks for, besides chatting.
	PermsVoice = PermConnect | PermSpeak
)

// Fingerprint is the part of a key shown for people to compare: 32 hex
// characters (128 bits), too many to forge a look-alike for.
func Fingerprint(keyHex string) string {
	if len(keyHex) > 32 {
		return keyHex[:32]
	}
	return keyHex
}
