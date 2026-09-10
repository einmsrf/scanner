package semantic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustClient(t *testing.T, baseURL string, maxBatch int) *Client {
	t.Helper()
	c, err := New(Options{
		BaseURL:  baseURL,
		APIKey:   "sk-test-key",
		Model:    "deepseek-chat",
		Timeout:  5 * time.Second,
		MaxBatch: maxBatch,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// chatServer 模拟 OpenAI 兼容接口，content 为模型回复内容。
func chatServer(t *testing.T, content string, status int) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()
	var calls atomic.Int32
	var lastAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		lastAuth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(404)
			return
		}
		if status >= 400 {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"error":{"message":"invalid api key","type":"auth_error"}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":{"message":"bad request: %v"}}`, err)
			return
		}
		resp := chatResponse{}
		resp.Choices = append(resp.Choices, struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}{})
		resp.Choices[0].Message.Content = content
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	return srv, &calls, &lastAuth
}

func TestNewRequiresAPIKey(t *testing.T) {
	if _, err := New(Options{BaseURL: "https://x/v1", Model: "m"}); err != ErrDisabled {
		t.Errorf("err = %v, want ErrDisabled（无 api_key 应静默降级）", err)
	}
	if _, err := New(Options{APIKey: "k", Model: "m"}); err == nil {
		t.Error("缺少 base_url 应报错")
	}
	if _, err := New(Options{APIKey: "k", BaseURL: "https://x/v1"}); err == nil {
		t.Error("缺少 model 应报错")
	}
}

func TestScoreParsesBareArray(t *testing.T) {
	content := `[{"item":"a","is_sensitive":true,"reason":"真实密钥","confidence":0.95},` +
		`{"item":"b","is_sensitive":false,"reason":"占位符","confidence":0.9}]`
	srv, calls, auth := chatServer(t, content, 200)
	defer srv.Close()

	c := mustClient(t, srv.URL+"/v1", 10)
	defer c.Close()

	got, err := c.Score(context.Background(), []Item{
		{ID: "a", Text: "secret=abc", Kind: KindSnippet},
		{ID: "b", Text: "secret=xxx", Kind: KindSnippet},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("verdicts = %d, want 2", len(got))
	}
	if !got[0].IsSensitive || got[0].Confidence != 0.95 || got[0].Reason != "真实密钥" {
		t.Errorf("verdict[0] = %+v", got[0])
	}
	if got[1].IsSensitive {
		t.Errorf("verdict[1] = %+v, want 非敏感", got[1])
	}
	if calls.Load() != 1 {
		t.Errorf("请求数 = %d, want 1（批量一次请求）", calls.Load())
	}
	if a, _ := auth.Load().(string); a != "Bearer sk-test-key" {
		t.Errorf("Authorization = %q, want Bearer sk-test-key", a)
	}
}

func TestScoreParsesFencedAndWrappedJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"裸数组带前后文字", "判定结果如下：\n[{\"item\":\"a\",\"is_sensitive\":true,\"reason\":\"r\",\"confidence\":0.8}]\n完毕"},
		{"markdown 代码块", "```json\n[{\"item\":\"a\",\"is_sensitive\":true,\"reason\":\"r\",\"confidence\":0.8}]\n```"},
		{"包在 results 里", `{"results":[{"item":"a","is_sensitive":true,"reason":"r","confidence":0.8}]}`},
		{"包在 items 里", `{"items":[{"item":"a","is_sensitive":true,"reason":"r","confidence":0.8}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _, _ := chatServer(t, c.content, 200)
			defer srv.Close()
			cl := mustClient(t, srv.URL+"/v1", 10)
			defer cl.Close()

			got, err := cl.Score(context.Background(), []Item{{ID: "a", Text: "t"}})
			if err != nil {
				t.Fatalf("Score: %v", err)
			}
			if len(got) != 1 || !got[0].IsSensitive || !got[0].Judged {
				t.Errorf("verdict = %+v, want 已判定且敏感", got)
			}
		})
	}
}

func TestScoreRejectsGarbageOutput(t *testing.T) {
	srv, _, _ := chatServer(t, "抱歉，我无法完成这个请求。", 200)
	defer srv.Close()
	c := mustClient(t, srv.URL+"/v1", 10)
	defer c.Close()

	if _, err := c.Score(context.Background(), []Item{{ID: "a", Text: "t"}}); err == nil {
		t.Fatal("err = nil, want 解析失败")
	}
}

func TestScoreHTTPErrorSurfaces(t *testing.T) {
	srv, _, _ := chatServer(t, "", 401)
	defer srv.Close()
	c := mustClient(t, srv.URL+"/v1", 10)
	defer c.Close()

	_, err := c.Score(context.Background(), []Item{{ID: "a", Text: "t"}})
	if err == nil {
		t.Fatal("err = nil, want 401 报错")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want 含状态码", err)
	}
}

func TestScoreEmptyItemsMakesNoRequest(t *testing.T) {
	srv, calls, _ := chatServer(t, "[]", 200)
	defer srv.Close()
	c := mustClient(t, srv.URL+"/v1", 10)
	defer c.Close()

	got, err := c.Score(context.Background(), nil)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
	if calls.Load() != 0 {
		t.Errorf("请求数 = %d, want 0（空输入不应发请求）", calls.Load())
	}
}

func TestScoreBatchesLargeInput(t *testing.T) {
	// 每批都要返回对应 item 的结果
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		json.Unmarshal(body, &req)
		user := req.Messages[len(req.Messages)-1].Content
		var raws []rawVerdict
		for _, line := range strings.Split(user, "\n") {
			if id, ok := strings.CutPrefix(line, "item: "); ok {
				id = strings.TrimSpace(id)
				if id != "" {
					raws = append(raws, rawVerdict{Item: id, IsSensitive: true, Reason: "r", Confidence: 0.5})
				}
			}
		}
		out, _ := json.Marshal(raws)
		resp := chatResponse{}
		resp.Choices = append(resp.Choices, struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}{})
		resp.Choices[0].Message.Content = string(out)
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, 3) // 每批 3 条
	defer c.Close()

	items := make([]Item, 7)
	for i := range items {
		items[i] = Item{ID: fmt.Sprintf("id%d", i), Text: "t", Kind: KindEndpoint}
	}
	got, err := c.Score(context.Background(), items)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("verdicts = %d, want 7", len(got))
	}
	for i, v := range got {
		if !v.Judged || v.ID != fmt.Sprintf("id%d", i) {
			t.Errorf("verdict[%d] = %+v, want 已判定且 ID 对应", i, v)
		}
	}
}

func TestScoreRespectsMaxItems(t *testing.T) {
	var sent int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		json.Unmarshal(body, &req)
		user := req.Messages[len(req.Messages)-1].Content
		n := strings.Count(user, "\nitem: ")
		atomic.AddInt32(&sent, int32(n))
		resp := chatResponse{}
		resp.Choices = append(resp.Choices, struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}{})
		resp.Choices[0].Message.Content = "[]"
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c, err := New(Options{BaseURL: srv.URL, APIKey: "k", Model: "m", MaxItems: 5, MaxBatch: 100})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	items := make([]Item, 20)
	for i := range items {
		items[i] = Item{ID: fmt.Sprintf("id%d", i), Text: "t"}
	}
	got, _ := c.Score(context.Background(), items)
	if len(got) != 5 {
		t.Errorf("verdicts = %d, want 5（受 MaxItems 限制）", len(got))
	}
	if atomic.LoadInt32(&sent) > 5 {
		t.Errorf("发送条目数 = %d, want <= 5", sent)
	}
}

func TestScorePartialBatchFailureDegradesGracefully(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 第一批成功，第二批失败
		if atomic.AddInt32(&n, 1) == 2 {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":{"message":"server error"}}`)
			return
		}
		resp := chatResponse{}
		resp.Choices = append(resp.Choices, struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}{})
		resp.Choices[0].Message.Content = `[{"item":"id0","is_sensitive":true,"reason":"r","confidence":0.9}]`
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := mustClient(t, srv.URL, 1) // 每个 item 一批 → 2 批
	defer c.Close()

	got, err := c.Score(context.Background(), []Item{{ID: "id0", Text: "t"}, {ID: "id1", Text: "t"}})
	if err == nil {
		t.Error("err = nil, want 记录到批次失败")
	}
	if len(got) != 2 {
		t.Fatalf("verdicts = %d, want 2（失败的条目按未判定占位）", len(got))
	}
	if !got[0].Judged {
		t.Error("第一批应已判定")
	}
	if got[1].Judged {
		t.Error("第二批失败，应保持未判定而不是报错中断")
	}
}

func TestScoreIgnoresUnknownAndDuplicateItems(t *testing.T) {
	content := `[{"item":"unknown","is_sensitive":true,"reason":"r","confidence":1},
	             {"item":"a","is_sensitive":true,"reason":"r","confidence":2}]`
	srv, _, _ := chatServer(t, content, 200)
	defer srv.Close()
	c := mustClient(t, srv.URL+"/v1", 10)
	defer c.Close()

	got, err := c.Score(context.Background(), []Item{{ID: "a", Text: "t"}})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !got[0].IsSensitive {
		t.Error("应命中 item a")
	}
	// 置信度应被钳制到 1
	if got[0].Confidence != 1 {
		t.Errorf("Confidence = %v, want 钳制到 1", got[0].Confidence)
	}
}

func TestPromptIncludesAllItemsAndSchema(t *testing.T) {
	items := []Item{
		{ID: "s1", Text: "password:\"abc\"", Kind: KindSnippet},
		{ID: "e1", Text: "/api/admin/delete", Kind: KindEndpoint},
	}
	p := buildUserPrompt(items)
	for _, want := range []string{"item: s1", "item: e1", "snippet", "endpoint", "is_sensitive", "confidence"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt 缺少 %q\n%s", want, p)
		}
	}
	if !strings.Contains(systemPrompt, "JSON") {
		t.Error("system prompt 应要求 JSON 输出")
	}
}

func TestClipTextTruncates(t *testing.T) {
	long := strings.Repeat("a", 100)
	got := clipText(long, 10)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("got = %q, want 截断并带省略号", got)
	}
	if got := clipText("a\nb\tc", 100); got != "a b c" {
		t.Errorf("got = %q, want 压成单行", got)
	}
}

func TestStripFences(t *testing.T) {
	cases := map[string]string{
		"```json\n[1]\n```": "[1]",
		"```\n[1]\n```":     "[1]",
		"[1]":               "[1]",
		"":                  "",
	}
	for in, want := range cases {
		if got := stripFences(in); got != want {
			t.Errorf("stripFences(%q) = %q, want %q", in, got, want)
		}
	}
}
