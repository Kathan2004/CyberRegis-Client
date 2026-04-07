"use client";

import { useState, useEffect, useRef } from "react";
import { MessageSquare } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils"; // Assuming Shadcn's cn utility is available

// Interface for API responses (chatbot-specific)
interface ScanResult {
  data?: {
    query?: string;
    response?: string;
    model?: string;
  };
  formatted?: string;
  status: "success" | "error";
  timestamp?: string;
  message?: string;
}

// Interface for chatbot messages
interface ChatMessage {
  id: number;
  text: string;
  isUser: boolean;
  timestamp: string | null;
}

// Props for the reusable Chatbot component
interface ChatbotProps {
  apiEndpoint?: string;
  className?: string;
  initialMessages?: ChatMessage[];
}

export default function Chatbot({
  apiEndpoint = "http://localhost.com:4000/api/chat",
  className,
  initialMessages = [],
}: ChatbotProps) {
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>(initialMessages);
  const [chatInput, setChatInput] = useState("");
  const [loading, setLoading] = useState(false);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const formatResults = (results: ScanResult | null): JSX.Element => {
    if (!results) return <></>;
    if (results.status === "error") {
      return <p>{results.message || "An error occurred."}</p>;
    }
    if (results.formatted && results.data?.response) {
      return (
        <div>
          <p>
            <strong>Response:</strong> {results.data.response}
          </p>
          <details>
            <summary className="cursor-pointer text-primary">View Full Details</summary>
            <div className="bg-black p-4 rounded-md">
              <style jsx>{`
                .bg-black pre {
                  background: transparent !important;
                  color: #4ade80;
                  padding: 0;
                  border-radius: 0;
                }
              `}</style>
              <div dangerouslySetInnerHTML={{ __html: results.formatted }} />
            </div>
          </details>
        </div>
      );
    }
    return <pre>{JSON.stringify(results, null, 2)}</pre>;
  };

  const handleChatSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const newUserMessage: ChatMessage = {
      id: chatMessages.length + 1,
      text: chatInput,
      isUser: true,
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatMessages((prev) => [...prev, newUserMessage]);
    setChatInput("");
    setLoading(true);

    try {
      const response = await fetch(apiEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: chatInput }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! Status: ${response.status}, Message: ${errorText}`);
      }

      const data: ScanResult = await response.json();
      if (data.status === "success" && data.data?.response) {
        const botResponse: ChatMessage = {
          id: chatMessages.length + 2,
          text: data.data.response,
          isUser: false,
          timestamp: new Date().toLocaleTimeString(),
        };
        setChatMessages((prev) => [...prev, botResponse]);
      } else {
        const errorResponse: ChatMessage = {
          id: chatMessages.length + 2,
          text: data.message || "Failed to get a response. Please try again.",
          isUser: false,
          timestamp: new Date().toLocaleTimeString(),
        };
        setChatMessages((prev) => [...prev, errorResponse]);
      }
    } catch (error) {
      console.error("Chat request error:", error);
      const errorResponse: ChatMessage = {
        id: chatMessages.length + 2,
        text: `Error: ${error instanceof Error ? error.message : "Unknown error occurred"}`,
        isUser: false,
        timestamp: new Date().toLocaleTimeString(),
      };
      setChatMessages((prev) => [...prev, errorResponse]);
    }
    setLoading(false);
  };

  // Auto-scroll to bottom of chat
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages]);

  return (
    <Card className={cn("border-primary/20 bg-card/50 backdrop-blur-sm p-6", className)}>
      <div className="space-y-6">
        <div className="space-y-2">
          <h2 className="text-2xl font-semibold flex items-center">
            <MessageSquare className="w-6 h-6 text-primary mr-2" />
            CyberRegis Assistant
          </h2>
          <p className="text-sm text-muted-foreground">
            Ask questions about cyber threats, scan results, or security best practices
          </p>
        </div>
        <Separator />
        <ScrollArea className="h-[300px] w-full rounded-md bg-background/30 p-4" ref={chatScrollRef}>
          {chatMessages.length === 0 ? (
            <div className="text-center text-muted-foreground text-sm">
              Start a conversation with the CyberRegis Assistant
            </div>
          ) : (
            chatMessages.map((message) => (
              <div
                key={message.id}
                className={`mb-4 flex ${message.isUser ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[70%] rounded-lg p-3 ${message.isUser
                      ? "bg-primary/20 text-primary-foreground"
                      : "bg-secondary/50 text-foreground"
                    }`}
                >
                  <p className="text-sm text-white">{message.text}</p>
                  <span className="text-xs text-muted-foreground mt-1 block">
                    {message.timestamp}
                  </span>
                </div>
              </div>
            ))
          )}
        </ScrollArea>
        <form onSubmit={handleChatSubmit} method="POST" className="flex space-x-2">
          <Input
            type="text"
            placeholder="Ask a question..."
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            className="bg-background border-input !text-white"
            style={{ color: '#FFFFFF' }}
          />
          <Button
            type="submit"
            disabled={loading || !chatInput.trim()}
            className="bg-primary hover:bg-primary/90"
          >
            {loading ? "Sending..." : "Send"}
          </Button>
        </form>
      </div>
    </Card>
  );
}