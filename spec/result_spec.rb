# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Result do
  it "maps CallbackPayload JSON to symbol-keyed, frozen accessors with markdown draft/note" do
    result = described_class.from_payload(
      "analysis_id" => "run-1",
      "project_id" => "11111111-1111-1111-1111-111111111111",
      "metadata" => {"resource_type" => "SupportTicket", "resource_id" => 42},
      "draft" => {"body_markdown" => "**hi**", "body_html" => "<b>hi</b>"},
      "notes" => [
        {"kind" => "summary", "body_markdown" => "the summary [trace](https://x)", "body_html" => "<p>s</p>"},
        {"kind" => "widget", "body_markdown" => "a widget", "body_html" => "<p>w</p>"}
      ],
      "actions" => [{"id" => "a1", "slug" => "recompute_record_formulas", "label" => "Approve", "description" => "d", "url" => "https://x", "color" => "green"}],
      "attachments" => [{"filename" => "f.txt", "mime_type" => "text/plain", "content_base64" => "eA=="}]
    )

    expect(result.analysis_id).to eq("run-1")
    expect(result.project_id).to eq("11111111-1111-1111-1111-111111111111")
    expect(result.metadata).to eq({resource_type: "SupportTicket", resource_id: 42})
    expect(result.draft).to eq("**hi**")
    expect(result.note).to eq("the summary [trace](https://x)")
    expect(result.actions.first[:slug]).to eq("recompute_record_formulas")
    expect(result.actions.first[:id]).to eq("a1")
    expect(result.actions.first[:label]).to eq("Approve")
    expect(result.actions.first[:url]).to eq("https://x")
    expect(result.actions.first[:color]).to eq("green")
    expect(result.actions.first[:description]).to eq("d")
    expect(result.attachments.first[:filename]).to eq("f.txt")
    expect(result).to be_frozen
    expect(result.metadata).to be_frozen
  end

  describe "draft (markdown)" do
    it "falls back to body_html only when markdown is absent" do
      result = described_class.from_payload("draft" => {"body_html" => "<p>only html</p>"})
      expect(result.draft).to eq("<p>only html</p>")
    end

    it "is nil when the draft node is absent or empty" do
      expect(described_class.from_payload({}).draft).to be_nil
      expect(described_class.from_payload("draft" => {"body_markdown" => ""}).draft).to be_nil
    end
  end

  describe "note (summary note, markdown)" do
    it "selects the summary by the host's `key`, in either array order" do
      summary = {"key" => "summary", "body_markdown" => "the summary"}
      trace = {"key" => "trace", "body_markdown" => "[trace](https://trace)"}

      expect(described_class.from_payload("notes" => [summary, trace]).note).to eq("the summary")
      expect(described_class.from_payload("notes" => [trace, summary]).note).to eq("the summary")
    end

    it "accepts legacy `kind` as a fallback discriminator" do
      result = described_class.from_payload(
        "notes" => [
          {"kind" => "trace", "body_markdown" => "trace"},
          {"kind" => "summary", "body_markdown" => "the summary"}
        ]
      )
      expect(result.note).to eq("the summary")
    end

    it "falls back to the first note when none is marked summary" do
      result = described_class.from_payload("notes" => [{"body_markdown" => "lone note"}])
      expect(result.note).to eq("lone note")
    end

    it "is nil when notes is absent or empty" do
      expect(described_class.from_payload({}).note).to be_nil
      expect(described_class.from_payload("notes" => []).note).to be_nil
    end
  end

  it "exposes the run-page link via metadata[:run_url], not via a note" do
    result = described_class.from_payload(
      "metadata" => {"run_url" => "https://run/run-1"},
      "notes" => [{"key" => "summary", "body_markdown" => "the summary"}]
    )
    expect(result.metadata[:run_url]).to eq("https://run/run-1")
    expect(result.note).to eq("the summary")
  end

  it "exposes the session_id from the result envelope" do
    result = described_class.from_payload("analysis_id" => "r", "session_id" => "sess-1")
    expect(result.session_id).to eq("sess-1")
  end

  it "exposes the project_id selected by map-mode authentication" do
    result = described_class.from_payload("analysis_id" => "r", "project_id" => "11111111-1111-1111-1111-111111111111")
    expect(result.project_id).to eq("11111111-1111-1111-1111-111111111111")
  end

  it "leaves session_id nil when the envelope omits it" do
    expect(described_class.from_payload("analysis_id" => "r").session_id).to be_nil
  end

  it "is ok? when there is no decline" do
    expect(described_class.from_payload("analysis_id" => "r").ok?).to be(true)
  end

  it "is not ok? when declined, exposing the reason" do
    result = described_class.from_payload(
      "analysis_id" => "r", "decline" => {"reason" => "out of scope"}
    )
    expect(result.ok?).to be(false)
    expect(result.decline).to eq({reason: "out of scope"})
  end

  it "defaults absent optional fields to nil and absent collections to empty" do
    result = described_class.from_payload("analysis_id" => "r")
    expect(result.draft).to be_nil
    expect(result.note).to be_nil
    expect(result.decline).to be_nil
    expect(result.metadata).to eq({})
    expect(result.actions).to eq([])
    expect(result.executed_actions).to eq([])
    expect(result.questions).to eq([])
    expect(result.delete_ids).to eq([])
    expect(result.attachments).to eq([])
  end

  it "surfaces executed_actions (already-run, render as outcomes), questions and delete" do
    result = described_class.from_payload(
      "executed_actions" => [
        {"id" => "ar-1", "slug" => "recompute_record_formulas", "label" => "Recompute", "ok" => true, "summary" => "42 rows"}
      ],
      "questions" => [{"id" => "q1", "text" => "Which environment?"}],
      "delete" => ["summary", "trace"]
    )

    executed = result.executed_actions.first
    expect(executed[:id]).to eq("ar-1")
    expect(executed[:slug]).to eq("recompute_record_formulas")
    expect(executed[:label]).to eq("Recompute")
    expect(executed[:ok]).to be(true)
    expect(executed[:summary]).to eq("42 rows")
    # Proposals and already-run actions are separate lists — never render an
    # executed action as a confirm button.
    expect(result.actions).to eq([])
    expect(result.questions.first[:text]).to eq("Which environment?")
    # `delete` is a reserved word; the wire key stays `delete`.
    expect(result.delete_ids).to eq(["summary", "trace"])
  end

  it "accepts already-symbol-keyed input too" do
    result = described_class.from_payload(analysis_id: "r", metadata: {resource_id: 7})
    expect(result.metadata).to eq({resource_id: 7})
  end
end
