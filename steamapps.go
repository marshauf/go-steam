package steam

import (
	"code.google.com/p/goprotobuf/proto"
	"github.com/Philipp15b/go-steam"
	"github.com/Philipp15b/go-steam/internal"
	"github.com/Philipp15b/go-steam/internal/protobuf"
	"github.com/Philipp15b/go-steam/internal/steamlang"
	"github.com/Philipp15b/keyvalues"

	"bytes"
)

type AppInfoEvent struct {
	ID           uint32
	ChangeNumber uint32
	Sections     map[uint32]*keyvalues.KeyValue
}

type PICSProductInfoEvent struct {
	Apps              []*PICSProductInfo
	UnknownAppIDs     []uint32
	Packages          []*PICSProductInfo
	UnknownPackageids []uint32
	MetaDataOnly      bool
	ResponsePending   bool
	HttpMinSize       uint32
	HttpHost          string
}

type PICSProductInfo struct {
	// ID of the app or package
	ID uint32
	// Current change number for the app or package
	ChangeNumber uint32
	// Was an access token required
	MissingToken bool
	// Hash of the content
	Sha []byte
	// For an app request, if only the public information was requested
	OnlyPublic bool

	KeyValues *keyvalues.KeyValue
}

type PICSChangesSinceEvent struct {
	CurrentChangeNumber uint32
	SinceChangeNumber   uint32
	ForceFullUpdate     bool
	PackageChanges      []Change
	AppChanges          []Change
}

type PICSTokensEvent struct {
	AppTokens     map[uint32]uint64
	PackageTokens map[uint32]uint64

	AppTokensDenied     []uint32
	PackageTokensDenied []uint32
}

type Change struct {
	ID           uint32
	ChangeNumber uint32
	NeedsToken   bool
}

type AppChangesEvent struct {
	CurrentChangeNumber uint32
	ForceFullUpdate     bool
	AppIDs              []uint32
}

type SteamApps struct {
	client *steam.Client
}

func NewSteamApps(client *steam.Client) *SteamApps {
	return &SteamApps{
		client: client,
	}
}

func (sa *SteamApps) HandlePacket(packet *internal.Packet) {
	switch packet.EMsg {
	case steamlang.EMsg_ClientAppInfoChanges:
		sa.handleAppInfoChanges(packet)
	case steamlang.EMsg_ClientAppInfoResponse:
		sa.handleAppInfoResponse(packet)
	case steamlang.EMsg_ClientPICSAccessTokenResponse:
		sa.handlePICSAccessTokenResponse(packet)
	case steamlang.EMsg_ClientPICSChangesSinceResponse:
		sa.handlePICSChangesSinceResponse(packet)
	case steamlang.EMsg_ClientPICSProductInfoResponse:
		sa.handlePICSProductInfoResponse(packet)
	}
}

func (sa *SteamApps) handleAppInfoChanges(packet *internal.Packet) {
	if !packet.IsProto {
		sa.client.Fatalf("Got non-proto AppInfoChanges response!")
		return
	}
	body := &protobuf.CMsgClientAppInfoChanges{}
	packet.ReadProtoMsg(body)

	event := AppChangesEvent{
		AppIDs:              body.GetAppIDs(),
		CurrentChangeNumber: body.GetCurrentChangeNumber(),
		ForceFullUpdate:     body.GetForceFullUpdate(),
	}
	sa.client.Emit(event)
}

func (sa *SteamApps) handleAppInfoResponse(packet *internal.Packet) {
	if !packet.IsProto {
		sa.client.Fatalf("Got non-proto AppInfo response!")
		return
	}
	body := &protobuf.CMsgClientAppInfoResponse{}
	packet.ReadProtoMsg(body)

	apps := body.GetApps()
	for _, app := range apps {
		event := AppInfoEvent{
			ID:           app.GetAppId(),
			ChangeNumber: app.GetChangeNumber(),
			Sections:     make(map[uint32]*keyvalues.KeyValue),
		}
		for _, section := range app.GetSections() {
			b := section.GetSectionKv()
			kv, err := keyvalues.UnmarshalBinary(bytes.NewReader(b))
			if err != nil {
				sa.client.Errorf("%s", err)
				continue
			}
			if kv.Children != nil {
				event.Sections[section.GetSectionId()] = kv
			}
		}
		sa.client.Emit(event)
	}
}

func (sa *SteamApps) handlePICSAccessTokenResponse(packet *internal.Packet) {
	if !packet.IsProto {
		sa.client.Fatalf("Got non-proto PICSChangesSince response!")
		return
	}
	body := &protobuf.CMsgClientPICSAccessTokenResponse{}
	packet.ReadProtoMsg(body)

	event := &PICSTokensEvent{
		AppTokens:           make(map[uint32]uint64),
		PackageTokens:       make(map[uint32]uint64),
		AppTokensDenied:     body.GetAppDeniedTokens(),
		PackageTokensDenied: body.GetPackageDeniedTokens(),
	}

	for _, token := range body.GetAppAccessTokens() {
		event.AppTokens[token.GetAppid()] = token.GetAccessToken()
	}
	for _, token := range body.GetPackageAccessTokens() {
		event.PackageTokens[token.GetPackageid()] = token.GetAccessToken()
	}

	sa.client.Emit(event)
}

func (sa *SteamApps) handlePICSChangesSinceResponse(packet *internal.Packet) {
	if !packet.IsProto {
		sa.client.Fatalf("Got non-proto PICSChangesSince response!")
		return
	}
	body := &protobuf.CMsgClientPICSChangesSinceResponse{}
	packet.ReadProtoMsg(body)

	protoAppChanges := body.GetAppChanges()
	appChanges := make([]Change, len(protoAppChanges))
	for i, pac := range protoAppChanges {
		appChanges[i] = Change{
			ID:           pac.GetAppid(),
			ChangeNumber: pac.GetChangeNumber(),
			NeedsToken:   pac.GetNeedsToken(),
		}
	}

	protoPackageChanges := body.GetPackageChanges()
	packageChanges := make([]Change, len(protoPackageChanges))
	for i, ppc := range protoPackageChanges {
		packageChanges[i] = Change{
			ID:           ppc.GetPackageid(),
			ChangeNumber: ppc.GetChangeNumber(),
			NeedsToken:   ppc.GetNeedsToken(),
		}
	}

	sa.client.Emit(&PICSChangesSinceEvent{
		CurrentChangeNumber: body.GetCurrentChangeNumber(),
		SinceChangeNumber:   body.GetSinceChangeNumber(),
		ForceFullUpdate:     body.GetForceFullUpdate(),
		PackageChanges:      packageChanges,
		AppChanges:          appChanges,
	})
}

func (sa *SteamApps) handlePICSProductInfoResponse(packet *internal.Packet) {
	if !packet.IsProto {
		sa.client.Fatalf("Got non-proto PICSProductInfo response!")
		return
	}
	body := &protobuf.CMsgClientPICSProductInfoResponse{}
	packet.ReadProtoMsg(body)

	protoApps := body.GetApps()
	apps := make([]*PICSProductInfo, len(protoApps))
	for i, pa := range protoApps {
		b := pa.GetBuffer()

		kv, err := keyvalues.Unmarshal(b)
		if err != nil {
			sa.client.Errorf("%s", err)
		}

		apps[i] = &PICSProductInfo{
			ID:           pa.GetAppid(),
			ChangeNumber: pa.GetChangeNumber(),
			MissingToken: pa.GetMissingToken(),
			Sha:          pa.GetSha(),
			OnlyPublic:   pa.GetOnlyPublic(),
			KeyValues:    kv,
		}
	}

	protoPackages := body.GetPackages()
	packages := make([]*PICSProductInfo, len(protoPackages))
	for i, pp := range protoPackages {
		b := pp.GetBuffer()
		if len(b) > 4 {
			b = b[4:] // For some reason the ProductInfo has a leading uint32
		}

		kv, err := keyvalues.UnmarshalBinary(bytes.NewReader(b))
		if err != nil {
			sa.client.Errorf("%s", err)
		}

		packages[i] = &PICSProductInfo{
			ID:           pp.GetPackageid(),
			ChangeNumber: pp.GetChangeNumber(),
			MissingToken: pp.GetMissingToken(),
			Sha:          pp.GetSha(),
			KeyValues:    kv,
		}
	}

	sa.client.Emit(&PICSProductInfoEvent{
		Apps:              apps,
		UnknownAppIDs:     body.GetUnknownAppids(),
		Packages:          packages,
		UnknownPackageids: body.GetUnknownPackageids(),
		MetaDataOnly:      body.GetMetaDataOnly(),
		ResponsePending:   body.GetResponsePending(),
		HttpMinSize:       body.GetHttpMinSize(),
		HttpHost:          body.GetHttpHost(),
	})
}

// Requests a list of app changes since the last provided change number value.
func (sa *SteamApps) GetAppChanges(lastChangenumber uint32, sendChangelist bool) {
	req := &protobuf.CMsgClientAppInfoUpdate{
		LastChangenumber: proto.Uint32(lastChangenumber),
		SendChangelist:   proto.Bool(sendChangelist),
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientAppInfoUpdate, req))
}

// Requests app information for a single app. Use the overload for requesting information on a batch of apps.
func (sa *SteamApps) GetAppInfo(appIDs ...uint32) {
	apps := make([]*protobuf.CMsgClientAppInfoRequest_App, len(appIDs))
	for i, id := range appIDs {
		apps[i] = &protobuf.CMsgClientAppInfoRequest_App{
			AppId: proto.Uint32(id),
		}
	}
	req := &protobuf.CMsgClientAppInfoRequest{
		Apps:            apps,
		SupportsBatches: proto.Bool(false),
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientAppInfoRequest, req))
}

// Requests an app ownership ticket for the specified AppID.
func (sa *SteamApps) GetAppOwnershipTicket(appID uint32) {
	req := &protobuf.CMsgClientGetAppOwnershipTicket{
		AppId: proto.Uint32(appID),
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientGetAppOwnershipTicket, req))
}

// Request the depot decryption key for a specified DepotID.
func (sa *SteamApps) GetDepotDecryptionKey(depotID, appID uint32) {
	req := &protobuf.CMsgClientGetDepotDecryptionKey{
		DepotId: proto.Uint32(depotID),
		AppId:   proto.Uint32(appID),
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientGetDepotDecryptionKey, req))
}

// Requests package information for a single package.
func (sa *SteamApps) GetPackageInfo(pkgIDs []uint32, metaDataOnly bool) {
	req := &protobuf.CMsgClientPackageInfoRequest{
		PackageIds:   pkgIDs,
		MetaDataOnly: proto.Bool(metaDataOnly),
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientPackageInfoRequest, req))
}

// Request PICS access tokens for a list of app ids and package ids.
func (sa *SteamApps) PICSGetAccessTokens(pkgIDs, appIDs []uint32) {
	req := &protobuf.CMsgClientPICSAccessTokenRequest{
		Packageids: pkgIDs,
		Appids:     appIDs,
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientPICSAccessTokenRequest, req))
}

// Request changes for apps and packages since a given change number.
func (sa *SteamApps) PICSGetChangesSince(sinceChangeNumber uint32, sendAppInfoChanges, sendPackageInfoChanges bool) {
	req := &protobuf.CMsgClientPICSChangesSinceRequest{
		SinceChangeNumber:      proto.Uint32(sinceChangeNumber),
		SendAppInfoChanges:     proto.Bool(sendAppInfoChanges),
		SendPackageInfoChanges: proto.Bool(sendPackageInfoChanges),
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientPICSChangesSinceRequest, req))
}

type PICSRequest struct {
	ID          uint32
	AccessToken uint64
	OnlyPublic  bool
}

// Request product information for a list of apps or packages.
func (sa *SteamApps) PICSGetProductInfo(pkgs, apps []PICSRequest, metaDataOnly bool) {
	req := &protobuf.CMsgClientPICSProductInfoRequest{
		Apps:         make([]*protobuf.CMsgClientPICSProductInfoRequest_AppInfo, len(apps)),
		Packages:     make([]*protobuf.CMsgClientPICSProductInfoRequest_PackageInfo, len(apps)),
		MetaDataOnly: proto.Bool(metaDataOnly),
	}

	for i, app := range apps {
		req.Apps[i] = &protobuf.CMsgClientPICSProductInfoRequest_AppInfo{
			Appid:       proto.Uint32(app.ID),
			AccessToken: proto.Uint64(app.AccessToken),
			OnlyPublic:  proto.Bool(app.OnlyPublic),
		}
	}
	for i, pkg := range pkgs {
		req.Packages[i] = &protobuf.CMsgClientPICSProductInfoRequest_PackageInfo{
			Packageid:   proto.Uint32(pkg.ID),
			AccessToken: proto.Uint64(pkg.AccessToken),
		}
	}
	sa.client.Write(internal.NewClientMsgProtobuf(steamlang.EMsg_ClientPICSProductInfoRequest, req))
}
