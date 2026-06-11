import { useState, useEffect, useRef } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import { Send, MessageSquare } from "lucide-react";
import { 
  getPentesterMessagesFromDesktop, 
  sendPentesterMessageFromDesktop,
  type ClientMessage 
} from "../lib/projectBridge";

interface ClientChatProps {
  projectId: string;
}

export function ClientChat({ projectId }: ClientChatProps) {
  const [messages, setMessages] = useState<ClientMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  const fetchMessages = async () => {
    try {
      const msgs = await getPentesterMessagesFromDesktop(projectId);
      setMessages(Array.isArray(msgs.messages) ? msgs.messages : []);
    } catch (err) {
      console.error("Failed to fetch client messages", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMessages();
    const interval = setInterval(fetchMessages, 5000); // Poll every 5s
    return () => clearInterval(interval);
  }, [projectId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    const text = input.trim();
    if (!text) return;
    
    setInput("");
    setSending(true);
    try {
      await sendPentesterMessageFromDesktop(projectId, text);
      await fetchMessages();
    } catch (err) {
      console.error("Failed to send message", err);
    } finally {
      setSending(false);
    }
  };

  return (
    <Card className="flex flex-col h-[400px] border-pf-500/20 bg-surface-1">
      <div className="flex items-center gap-2 p-3 border-b border-border bg-surface-2/30">
        <MessageSquare size={16} className="text-pf-400" />
        <h3 className="text-sm font-semibold text-text-primary">Client Q&A</h3>
      </div>
      
      <div className="flex-1 overflow-y-auto p-4 space-y-3" ref={scrollRef}>
        {loading && messages.length === 0 ? (
          <div className="text-center text-xs text-text-muted py-4">Loading messages...</div>
        ) : messages.length === 0 ? (
          <div className="text-center text-xs text-text-muted py-4 italic">No messages yet. When the client asks a question, it will appear here.</div>
        ) : (
          messages.map(msg => {
            const isMe = msg.sender === "pentester";
            return (
              <div key={msg.id} className={`flex flex-col max-w-[80%] ${isMe ? "ml-auto items-end" : "mr-auto items-start"}`}>
                <span className="text-[10px] text-text-muted mb-1 px-1">
                  {isMe ? "You" : "Client"} • {new Date(msg.created_at).toLocaleTimeString()}
                </span>
                <div className={`px-3 py-2 rounded-lg text-sm whitespace-pre-wrap break-words break-all min-w-0 ${isMe ? "bg-pf-600 text-white rounded-br-none" : "bg-surface-2 text-text-primary border border-border rounded-bl-none"}`}>
                  {msg.content}
                </div>
              </div>
            );
          })
        )}
      </div>
      
      <div className="p-3 border-t border-border flex gap-2">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleSend()}
          placeholder="Reply to client..."
          className="flex-1 bg-surface-2 border border-border rounded-md px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-pf-500/50"
          disabled={sending}
        />
        <Button size="sm" onClick={handleSend} loading={sending} disabled={sending || !input.trim()}>
          <Send size={14} />
        </Button>
      </div>
    </Card>
  );
}
