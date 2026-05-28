import {
  useState,
  useRef,
  useEffect,
  useCallback,
  type KeyboardEvent,
  type FormEvent,
} from "react";
import {
  Send,
  Bot,
  User,
  ChevronDown,
  ChevronRight,
  Loader2,
  AlertTriangle,
  CheckCircle,
  Clock,
  ShieldAlert,
} from "lucide-react";
import { clsx } from "clsx";
import { useAgentStore } from "@/stores/agentStore";
import { Button } from "@/components/ds/button";
import type { ChatMessage, ToolCallInfo, HITLCheckpoint } from "@/types/investigation";

// -- Tool Call Card (collapsible) --

interface ToolCallCardProps {
  toolCall: ToolCallInfo;
}

function ToolCallCard({ toolCall }: ToolCallCardProps) {
  const [expanded, setExpanded] = useState(false);

  const statusIcon = {
    pending: <Clock className="w-3.5 h-3.5 text-muted-foreground" />,
    running: <Loader2 className="w-3.5 h-3.5 text-amber-400 animate-spin" />,
    completed: <CheckCircle className="w-3.5 h-3.5 text-green-400" />,
    error: <AlertTriangle className="w-3.5 h-3.5 text-destructive" />,
  };

  return (
    <div
      className="bg-accent/50 border border-border/40 rounded-md my-1.5 text-xs overflow-hidden"
      data-testid={`agent-chat-tool-call-${toolCall.id}`}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 w-full px-3 py-2 hover:bg-accent transition-colors text-left"
        aria-expanded={expanded}
        data-testid={`agent-chat-tool-call-${toolCall.id}-toggle`}
      >
        {expanded ? (
          <ChevronDown className="w-3 h-3 text-muted-foreground shrink-0" aria-hidden="true" />
        ) : (
          <ChevronRight className="w-3 h-3 text-muted-foreground shrink-0" aria-hidden="true" />
        )}
        {statusIcon[toolCall.status]}
        <span className="font-mono text-foreground font-medium">
          {toolCall.name}
        </span>
        {toolCall.duration_ms !== undefined && (
          <span className="text-muted-foreground ml-auto">
            {toolCall.duration_ms}ms
          </span>
        )}
      </button>
      {expanded && (
        <div className="px-3 pb-2 space-y-2">
          {Object.keys(toolCall.arguments).length > 0 && (
            <div>
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                Arguments
              </span>
              <pre className="mt-1 text-muted-foreground font-mono text-[11px] bg-card/50 rounded p-2 overflow-x-auto max-h-32">
                {JSON.stringify(toolCall.arguments, null, 2)}
              </pre>
            </div>
          )}
          {toolCall.result && (
            <div>
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                Result
              </span>
              <pre className="mt-1 text-muted-foreground font-mono text-[11px] bg-card/50 rounded p-2 overflow-x-auto max-h-48">
                {toolCall.result}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// -- HITL Checkpoint Card --

interface HITLCardProps {
  checkpoint: HITLCheckpoint;
  onRespond: (checkpointId: string, approved: boolean, comment?: string) => void;
}

function HITLCard({ checkpoint, onRespond }: HITLCardProps) {
  const [comment, setComment] = useState("");

  return (
    <div
      className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4 my-3 animate-slide-in"
      data-testid={`agent-chat-hitl-${checkpoint.id}`}
    >
      <div className="flex items-center gap-2 mb-2">
        <ShieldAlert className="w-5 h-5 text-purple-400" aria-hidden="true" />
        <span className="text-sm font-semibold text-purple-300">
          Approval Required
        </span>
      </div>
      <p className="text-sm text-foreground mb-2">{checkpoint.prompt}</p>
      {checkpoint.action && (
        <div className="bg-accent/50 rounded-md p-3 mb-3 text-xs font-mono text-muted-foreground">
          <div>
            Action: <span className="text-foreground">{checkpoint.action.action_type ?? "unknown"}</span>
          </div>
          <div>
            Target: <span className="text-foreground">{checkpoint.action.target ?? "unknown"}</span>
          </div>
          <div>
            Reason: <span className="text-foreground">{checkpoint.action.reason ?? ""}</span>
          </div>
        </div>
      )}
      <textarea
        placeholder="Optional comment..."
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        className="w-full bg-accent border border-border/50 rounded-md px-3 py-2 text-sm text-foreground placeholder-slate-500 mb-3 resize-none focus:outline-none focus:ring-2 focus:ring-purple-500/50"
        rows={2}
        aria-label="Approval comment"
        data-testid={`agent-chat-hitl-${checkpoint.id}-comment-input`}
      />
      <div className="flex items-center gap-3">
        <Button
          size="sm"
          onClick={() => onRespond(checkpoint.id, true, comment || undefined)}
          data-testid={`agent-chat-hitl-${checkpoint.id}-approve-button`}
        >
          Approve
        </Button>
        <Button
          variant="destructive"
          size="sm"
          onClick={() => onRespond(checkpoint.id, false, comment || undefined)}
          data-testid={`agent-chat-hitl-${checkpoint.id}-reject-button`}
        >
          Reject
        </Button>
      </div>
    </div>
  );
}

// -- Message Bubble --

interface MessageBubbleProps {
  message: ChatMessage;
}

function MessageBubble({ message }: MessageBubbleProps) {
  const isUser = message.role === "user";
  const isSystem = message.role === "system";

  return (
    <div
      className={clsx(
        "flex gap-3 animate-slide-in",
        isUser ? "flex-row-reverse" : "flex-row",
      )}
      data-testid={`agent-chat-message-${message.id}`}
      data-message-role={message.role}
    >
      {/* Avatar */}
      <div
        className={clsx(
          "w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5",
          isUser
            ? "bg-primary/30 border border-primary/30"
            : isSystem
              ? "bg-amber-600/30 border border-amber-500/30"
              : "bg-muted border border-border",
        )}
      >
        {isUser ? (
          <User className="w-3.5 h-3.5 text-primary" aria-hidden="true" />
        ) : (
          <Bot className="w-3.5 h-3.5 text-foreground" aria-hidden="true" />
        )}
      </div>

      {/* Content */}
      <div
        className={clsx(
          "max-w-[80%] rounded-xl px-4 py-2.5 text-sm leading-relaxed",
          isUser
            ? "bg-primary/20 border border-primary/20 text-foreground"
            : isSystem
              ? "bg-amber-500/10 border border-amber-500/20 text-amber-200"
              : "bg-accent/80 border border-border/40 text-foreground",
          !isUser && "font-mono text-[13px]",
        )}
      >
        {/* Whitespace-preserving content */}
        <div className="whitespace-pre-wrap break-words">{message.content}</div>

        {/* Tool calls */}
        {message.tool_calls && message.tool_calls.length > 0 && (
          <div className="mt-2">
            {message.tool_calls.map((tc) => (
              <ToolCallCard key={tc.id} toolCall={tc} />
            ))}
          </div>
        )}

        {/* Streaming indicator */}
        {message.is_streaming && (
          <span className="inline-block w-2 h-4 bg-blue-400 ml-0.5 animate-pulse rounded-sm" />
        )}
      </div>
    </div>
  );
}

// -- Main Agent Chat --

interface AgentChatProps {
  investigationId: string;
}

export function AgentChat({ investigationId }: AgentChatProps) {
  const {
    messages,
    pendingCheckpoints,
    isStreaming,
    streamingContent,
    sendMessage,
    respondToCheckpoint,
    loadHistory,
    setInvestigation,
    isLoadingHistory,
  } = useAgentStore();

  const [inputValue, setInputValue] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Initialize on mount / investigation change
  useEffect(() => {
    setInvestigation(investigationId);
    void loadHistory(investigationId);
  }, [investigationId, setInvestigation, loadHistory]);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamingContent]);

  const handleSend = useCallback(
    (e?: FormEvent) => {
      e?.preventDefault();
      const trimmed = inputValue.trim();
      if (!trimmed || isStreaming) return;

      void sendMessage(trimmed);
      setInputValue("");
      inputRef.current?.focus();
    },
    [inputValue, isStreaming, sendMessage],
  );

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    },
    [handleSend],
  );

  // Build display messages including streaming
  const displayMessages = [...messages];
  if (isStreaming && streamingContent) {
    displayMessages.push({
      id: "streaming",
      role: "assistant",
      content: streamingContent,
      timestamp: new Date().toISOString(),
      is_streaming: true,
    });
  }

  return (
    <div className="flex flex-col h-full" data-testid="agent-chat">
      {/* Messages area */}
      <div
        className="flex-1 overflow-y-auto px-4 py-4 space-y-4"
        data-testid="agent-chat-message-list"
      >
        {isLoadingHistory ? (
          <div
            className="flex items-center justify-center h-full"
            data-testid="agent-chat-loading"
          >
            <Loader2
              className="w-6 h-6 text-muted-foreground animate-spin"
              aria-label="Loading chat history"
            />
          </div>
        ) : displayMessages.length === 0 ? (
          <div
            className="flex flex-col items-center justify-center h-full text-muted-foreground"
            data-testid="agent-chat-empty"
          >
            <Bot className="w-10 h-10 mb-3 text-muted-foreground/60" aria-hidden="true" />
            <p className="text-sm font-medium text-muted-foreground">
              Investigation Agent
            </p>
            <p className="text-xs mt-1">
              Send a message to interact with the AI agent
            </p>
          </div>
        ) : (
          displayMessages.map((msg) => (
            <MessageBubble key={msg.id} message={msg} />
          ))
        )}

        {/* HITL Checkpoints */}
        {pendingCheckpoints.map((cp) => (
          <HITLCard
            key={cp.id}
            checkpoint={cp}
            onRespond={respondToCheckpoint}
          />
        ))}

        {/* Thinking indicator */}
        {isStreaming && !streamingContent && (
          <div
            className="flex items-center gap-3 animate-slide-in"
            data-testid="agent-chat-thinking"
          >
            <div className="w-7 h-7 rounded-full bg-muted border border-border flex items-center justify-center">
              <Bot className="w-3.5 h-3.5 text-foreground" aria-hidden="true" />
            </div>
            <div className="flex items-center gap-2 bg-accent/80 border border-border/40 rounded-xl px-4 py-3">
              <div className="flex gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce [animation-delay:0ms]" />
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce [animation-delay:150ms]" />
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-bounce [animation-delay:300ms]" />
              </div>
              <span className="text-xs text-muted-foreground ml-1">Thinking...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input bar */}
      <div className="shrink-0 border-t border-border/50 p-4 bg-card/50">
        <form
          onSubmit={handleSend}
          className="flex items-end gap-3"
          data-testid="agent-chat-form"
        >
          <textarea
            ref={inputRef}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Send a message to the agent..."
            rows={1}
            className="flex-1 bg-accent border border-border/50 rounded-lg px-4 py-2.5 text-sm text-foreground placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-primary/50 transition-colors max-h-32 overflow-y-auto"
            style={{
              minHeight: "40px",
              height: "auto",
            }}
            aria-label="Message to agent"
            data-testid="agent-chat-input"
          />
          <Button
            type="submit"
            
            disabled={!inputValue.trim() || isStreaming}
            className="shrink-0"
            aria-label="Send message"
            data-testid="agent-chat-send-button"
          >
            <Send className="w-4 h-4" aria-hidden="true" />
          </Button>
        </form>
      </div>
    </div>
  );
}
