package tradeoffer

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Philipp15b/go-steam/community"
	"github.com/Philipp15b/go-steam/economy/inventory"
	"github.com/Philipp15b/go-steam/netutil"
	"github.com/Philipp15b/go-steam/steamid"
	"net/http"
	"strconv"
)

type APIKey string

const apiUrl = "http://api.steampowered.com/IEconService/%s/v%d"

type Client struct {
	client    *http.Client
	key       APIKey
	sessionId string
}

func NewClient(key APIKey, sessionId, steamLogin string) *Client {
	c := &Client{
		new(http.Client),
		key,
		sessionId,
	}
	community.SetCookies(c.client, sessionId, steamLogin)
	return c
}

func (c *Client) GetOffers() (*TradeOffers, error) {
	resp, err := c.client.Get(fmt.Sprintf(apiUrl, "GetTradeOffers", 1) + "?" + netutil.ToUrlValues(map[string]string{
		"key":                 string(c.key),
		"get_sent_offers":     "1",
		"get_received_offers": "1",
	}).Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	t := new(struct {
		Response *TradeOffers
	})
	err = json.NewDecoder(resp.Body).Decode(t)
	if err != nil {
		return nil, err
	}
	return t.Response, nil
}

type actionResult struct {
	Success bool
	Error   string
}

func (c *Client) action(method string, version uint, id TradeOfferId) error {
	resp, err := c.client.Do(netutil.NewPostForm(fmt.Sprintf(apiUrl, method, version), netutil.ToUrlValues(map[string]string{
		"key":          string(c.key),
		"tradeofferid": strconv.FormatUint(uint64(id), 10),
	})))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(method + " error: status code not 200")
	}
	return nil
}

func (c *Client) Decline(id TradeOfferId) error {
	return c.action("DeclineTradeOffer", 1, id)
}

func (c *Client) Cancel(id TradeOfferId) error {
	return c.action("CancelTradeOffer", 1, id)
}

func (c *Client) Accept(id TradeOfferId) error {
	resp, err := c.client.PostForm(fmt.Sprintf("http://steamcommunity.com/tradeoffer/%d/accept", id), netutil.ToUrlValues(map[string]string{
		"sessionid":    c.sessionId,
		"serverid":     "1",
		"tradeofferid": strconv.FormatUint(uint64(id), 10),
	}))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("accept error: status code not 200")
	}
	return nil
}

type TradeItem struct {
	AppId     uint32
	ContextId uint64
	Amount    uint
	AssetId   uint64
}

// Sends a new trade offer to the given Steam user. You can optionally specify an access token if you've got one.
// In addition, `countered` can be non-nil, indicating the trade offer this is a counter for.
func (c *Client) Create(other steamid.SteamId, accessToken *string, myItems, theirItems []TradeItem, countered *TradeOfferId, message string) error {
	to := map[string]interface{}{
		"newversion": "true",
		"version":    "2",
		"me": map[string]interface{}{
			"assets":   myItems,
			"currency": make([]struct{}, 0),
			"ready":    "false",
		},
		"them": map[string]interface{}{
			"assets":   theirItems,
			"currency": make([]struct{}, 0),
			"ready":    "false",
		},
	}

	jto, err := json.Marshal(to)
	if err != nil {
		panic(err)
	}

	data := map[string]string{
		"sessionid":         c.sessionId,
		"serverid":          "1",
		"partner":           fmt.Sprintf("%d", other),
		"tradeoffermessage": message,
		"json_tradeoffer":   string(jto),
	}

	var referer string
	if countered != nil {
		referer = fmt.Sprintf("http://steamcommunity.com/tradeoffer/%d/", *countered)
		data["tradeofferid_countered"] = fmt.Sprintf("%d", *countered)
	} else {
		referer = fmt.Sprintf("http://steamcommunity.com/tradeoffer/new?partner=%d", other)
	}

	req := netutil.NewPostForm("http://steamcommunity.com/tradeoffer/new/send", netutil.ToUrlValues(data))
	req.Header.Add("Referer", referer)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("accept error: status code not 200")
	}
	return nil
}

func (c *Client) GetOwnInventory(contextId uint64, appId uint32) (*inventory.Inventory, error) {
	return inventory.GetOwnInventory(c.client, contextId, appId)
}

func (c *Client) GetTheirInventory(other steamid.SteamId, contextId uint64, appId uint32) (*inventory.Inventory, error) {
	return inventory.GetFullInventory(func() (*inventory.PartialInventory, error) {
		return c.getPartialTheirInventory(other, contextId, appId, nil)
	}, func(start uint) (*inventory.PartialInventory, error) {
		return c.getPartialTheirInventory(other, contextId, appId, &start)
	})
}

func (c *Client) getPartialTheirInventory(other steamid.SteamId, contextId uint64, appId uint32, start *uint) (*inventory.PartialInventory, error) {
	data := map[string]string{
		"sessionid": c.sessionId,
		"partner":   fmt.Sprintf("%d", other),
		"contextid": strconv.FormatUint(contextId, 10),
		"appid":     strconv.FormatUint(uint64(appId), 10),
	}
	if start != nil {
		data["start"] = strconv.FormatUint(uint64(*start), 10)
	}

	const baseUrl = "http://steamcommunity.com/tradeoffer/new/"
	req, err := http.NewRequest("GET", baseUrl+"partnerinventory/?"+netutil.ToUrlValues(data).Encode(), nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("Referer", baseUrl+"?partner="+fmt.Sprintf("%d", other))

	return inventory.DoInventoryRequest(c.client, req)
}
