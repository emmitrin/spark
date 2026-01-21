package opensearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	opensearch "github.com/opensearch-project/opensearch-go/v3"
	"github.com/opensearch-project/opensearch-go/v3/opensearchapi"
	"github.com/sirupsen/logrus"

	"github.com/emmitrin/spark/internal/models"
)

type Client struct {
	client    *opensearch.Client
	indexName string
	logger    *logrus.Logger
}

type Config struct {
	Addresses  []string
	Username   string
	Password   string
	IndexName  string
	UseTLS     bool
	SkipVerify bool
}

func NewClient(cfg Config, logger *logrus.Logger) (*Client, error) {
	opensearchConfig := opensearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
	}

	if cfg.UseTLS {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipVerify,
			},
		}
		opensearchConfig.Transport = transport
	}

	client, err := opensearch.NewClient(opensearchConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create opensearch client: %w", err)
	}

	osClient := &Client{
		client:    client,
		indexName: cfg.IndexName,
		logger:    logger,
	}

	if err := osClient.ensureIndex(); err != nil {
		return nil, fmt.Errorf("failed to ensure index: %w", err)
	}

	return osClient, nil
}

func (c *Client) ensureIndex() error {
	exists, err := c.indexExists()
	if err != nil {
		return err
	}

	if exists {
		return nil
	}

	mapping := map[string]interface{}{
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"task_id": map[string]interface{}{
					"type": "keyword",
				},
				"container_id": map[string]interface{}{
					"type": "keyword",
				},
				"timestamp": map[string]interface{}{
					"type": "date",
				},
				"ioc": map[string]interface{}{
					"type":    "object",
					"enabled": true,
				},
				"metadata": map[string]interface{}{
					"type":    "object",
					"enabled": true,
				},
			},
		},
	}

	mappingJSON, _ := json.Marshal(mapping)
	req := opensearchapi.IndicesCreateReq{
		Index: c.indexName,
		Body:  bytes.NewReader(mappingJSON),
	}

	opensearchRes, err := c.client.Do(context.Background(), req, nil)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer opensearchRes.Body.Close()

	if opensearchRes.IsError() {
		body, _ := io.ReadAll(opensearchRes.Body)
		return fmt.Errorf("error creating index: %s", string(body))
	}

	c.logger.Infof("Created OpenSearch index: %s", c.indexName)

	return nil
}

func (c *Client) indexExists() (bool, error) {
	req := opensearchapi.IndicesExistsReq{
		Indices: []string{c.indexName},
	}

	opensearchRes, err := c.client.Do(context.Background(), req, nil)
	if err != nil {
		return false, err
	}
	defer opensearchRes.Body.Close()

	return !opensearchRes.IsError(), nil
}

func (c *Client) IndexIoC(ctx context.Context, doc *models.IoCDocument) error {
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	req := opensearchapi.IndexReq{
		Index: c.indexName,
		Body:  bytes.NewReader(docJSON),
		Params: opensearchapi.IndexParams{
			Refresh: "true",
		},
	}

	var indexResp opensearchapi.IndexResp
	opensearchRes, err := c.client.Do(ctx, req, &indexResp)

	if err != nil {
		return fmt.Errorf("failed to index document: %w", err)
	}
	defer opensearchRes.Body.Close()

	if opensearchRes.IsError() {
		body, _ := io.ReadAll(opensearchRes.Body)
		return fmt.Errorf("error indexing document: %s", string(body))
	}

	c.logger.Debugf("Indexed IoC document for task %s", doc.TaskID)

	return nil
}

func (c *Client) SearchIoC(ctx context.Context, query map[string]interface{}) ([]*models.IoCDocument, error) {
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req := opensearchapi.SearchReq{
		Indices: []string{c.indexName},
		Body:    bytes.NewReader(queryJSON),
	}

	var searchResp opensearchapi.SearchResp
	opensearchRes, err := c.client.Do(ctx, req, &searchResp)

	if err != nil {
		return nil, fmt.Errorf("failed to search: %w", err)
	}
	defer opensearchRes.Body.Close()

	if opensearchRes.IsError() {
		body, _ := io.ReadAll(opensearchRes.Body)
		return nil, fmt.Errorf("error searching: %s", string(body))
	}

	documents := make([]*models.IoCDocument, 0, len(searchResp.Hits.Hits))

	for _, hit := range searchResp.Hits.Hits {
		var doc models.IoCDocument
		if err := json.Unmarshal(hit.Source, &doc); err != nil {
			c.logger.Warnf("Failed to unmarshal search hit: %v", err)
			continue
		}

		documents = append(documents, &doc)
	}

	return documents, nil
}

func (c *Client) Close() error {
	return nil
}
