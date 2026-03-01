package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mailclient/internal/config"
)

type githubClient struct {
	cfg     config.Config
	http    *http.Client
	baseURL string
}

func newGitHubClient(cfg config.Config) *githubClient {
	return &githubClient{
		cfg:     cfg,
		http:    &http.Client{Timeout: time.Duration(cfg.UpdateHTTPTimeoutSec) * time.Second},
		baseURL: "https://api.github.com",
	}
}

type githubRelease struct {
	TagName     string               `json:"tag_name"`
	Name        string               `json:"name"`
	PublishedAt string               `json:"published_at"`
	HTMLURL     string               `json:"html_url"`
	Assets      []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func (c *githubClient) latestRelease(ctx context.Context, etag string) (ReleaseInfo, string, bool, error) {
	out, newETag, notModified, err := c.latestReleaseRaw(ctx, etag)
	if err != nil {
		return ReleaseInfo{}, "", false, err
	}
	if notModified {
		return ReleaseInfo{}, newETag, true, nil
	}
	release, err := toReleaseInfo(out)
	if err != nil {
		return ReleaseInfo{}, "", false, err
	}
	return release, newETag, false, nil
}

func (c *githubClient) latestReleaseRaw(ctx context.Context, etag string) (githubRelease, string, bool, error) {
	path := fmt.Sprintf("/repos/%s/%s/releases/latest", url.PathEscape(c.cfg.UpdateRepoOwner), url.PathEscape(c.cfg.UpdateRepoName))
	var out githubRelease
	newETag, notModified, err := c.requestJSON(ctx, path, etag, &out)
	if err != nil {
		return githubRelease{}, "", false, err
	}
	return out, newETag, notModified, nil
}

func (c *githubClient) releaseByTag(ctx context.Context, tag string) (githubRelease, error) {
	path := fmt.Sprintf("/repos/%s/%s/releases/tags/%s",
		url.PathEscape(c.cfg.UpdateRepoOwner),
		url.PathEscape(c.cfg.UpdateRepoName),
		url.PathEscape(tag),
	)
	var out githubRelease
	_, _, err := c.requestJSON(ctx, path, "", &out)
	return out, err
}

func (c *githubClient) requestJSON(ctx context.Context, path, etag string, out any) (string, bool, error) {
	u := strings.TrimRight(c.baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mailclient-updater/1")
	if trimmed := strings.TrimSpace(c.cfg.UpdateGitHubToken); trimmed != "" {
		req.Header.Set("Authorization", "Bearer "+trimmed)
	}
	if strings.TrimSpace(etag) != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return resp.Header.Get("ETag"), true, nil
	case http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return "", false, err
		}
		return resp.Header.Get("ETag"), false, nil
	default:
		return "", false, fmt.Errorf("github api returned status %d", resp.StatusCode)
	}
}

func toReleaseInfo(in githubRelease) (ReleaseInfo, error) {
	tag := strings.TrimSpace(in.TagName)
	if tag == "" {
		return ReleaseInfo{}, fmt.Errorf("latest release has empty tag")
	}
	var publishedAt time.Time
	if strings.TrimSpace(in.PublishedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, in.PublishedAt)
		if err != nil {
			return ReleaseInfo{}, fmt.Errorf("invalid release timestamp: %w", err)
		}
		publishedAt = parsed
	}
	return ReleaseInfo{
		TagName:     tag,
		Name:        strings.TrimSpace(in.Name),
		PublishedAt: publishedAt,
		HTMLURL:     strings.TrimSpace(in.HTMLURL),
	}, nil
}

func findAssetURL(rel githubRelease, assetName string) (string, bool) {
	for _, a := range rel.Assets {
		if strings.EqualFold(strings.TrimSpace(a.Name), strings.TrimSpace(assetName)) && strings.TrimSpace(a.URL) != "" {
			return strings.TrimSpace(a.URL), true
		}
	}
	return "", false
}
