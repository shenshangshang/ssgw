// 协议转换：OpenAI Chat Completions ↔ Anthropic Messages；OpenAI Responses API ↔ Chat
'use strict';

// ============ OpenAI Chat → Anthropic Messages（上游侧） ============

function openaiToAnthropic(body) {
  const messages = [];
  let system;
  for (const m of body.messages || []) {
    if (m.role === 'system' || m.role === 'developer') {
      system = (system ? system + '\n\n' : '') + (typeof m.content === 'string' ? m.content : partsText(m.content));
      continue;
    }
    if (m.role === 'user' || m.role === 'assistant' || m.role === 'tool') {
      // 图片部分
      const blocks = [];
      const content = m.content;
      if (typeof content === 'string') blocks.push({ type: 'text', text: content });
      else if (Array.isArray(content)) {
        for (const p of content) {
          if (p.type === 'text') blocks.push({ type: 'text', text: p.text });
          else if (p.type === 'image_url') {
            const url = p.image_url?.url || '';
            const m2 = url.match(/^data:([^;]+);base64,(.+)$/);
            if (m2) blocks.push({ type: 'image', source: { type: 'base64', media_type: m2[1], data: m2[2] } });
          } else if (p.type === 'text/plain' || p.text) blocks.push({ type: 'text', text: p.text });
        }
      }
      if (m.role === 'tool') {
        messages.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: m.tool_call_id || '', content: blocks.length ? blocks : (typeof content === 'string' ? content : '') }] });
      } else if (blocks.length) {
        messages.push({ role: m.role, content: blocks });
      }
    }
  }
  // assistant 历史 tool_calls → tool_use 块（顺序对齐）
  for (const m of body.messages || []) {
    if (m.role === 'assistant' && Array.isArray(m.tool_calls)) {
      for (const tc of m.tool_calls || []) {
        const args = safeParse(tc.function?.arguments);
        messages.push({ role: 'assistant', content: [{ type: 'tool_use', id: tc.id, name: tc.function?.name, input: args }] });
      }
    }
  }
  const out = {
    model: body.model,
    messages: messages.length ? messages : [{ role: 'user', content: ' ' }],
    max_tokens: body.max_completion_tokens || body.max_tokens || 4096,
    stream: !!body.stream,
  };
  if (system) out.system = system;
  if (Array.isArray(body.tools)) {
    out.tools = body.tools.map(t => ({
      name: t.function?.name,
      description: t.function?.description || '',
      input_schema: t.function?.parameters || { type: 'object', properties: {} },
    })).filter(t => t.name);
  }
  if (body.temperature !== undefined) out.temperature = body.temperature;
  if (body.top_p !== undefined) out.top_p = body.top_p;
  if (body.stop) out.stop_sequences = Array.isArray(body.stop) ? body.stop : [body.stop];
  if (body.tool_choice?.type === 'function') out.tool_choice = { type: 'tool', name: body.tool_choice.function?.name };
  else if (body.tool_choice === 'required') out.tool_choice = { type: 'any' };
  else if (body.tool_choice === 'auto' && out.tools) out.tool_choice = { type: 'auto' };
  return out;
}

// Anthropic 非流式响应 → OpenAI Chat 格式
function anthropicToOpenai(json, model) {
  let content = '';
  const toolCalls = [];
  for (const block of json.content || []) {
    if (block.type === 'text') content += block.text;
    else if (block.type === 'tool_use') {
      toolCalls.push({ id: block.id, type: 'function', function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) } });
    }
  }
  const msg = { role: 'assistant', content: content || null };
  if (toolCalls.length) msg.tool_calls = toolCalls;
  return {
    id: json.id || 'chatcmpl-' + Math.random().toString(36).slice(2),
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: model || json.model,
    choices: [{ index: 0, message: msg, finish_reason: json.stop_reason === 'tool_use' ? 'tool_calls' : json.stop_reason === 'max_tokens' ? 'length' : 'stop' }],
    usage: {
      prompt_tokens: json.usage?.input_tokens ?? 0,
      completion_tokens: json.usage?.output_tokens ?? 0,
      total_tokens: (json.usage?.input_tokens ?? 0) + (json.usage?.output_tokens ?? 0),
    },
  };
}

// Anthropic SSE 事件 → OpenAI chunk 的转换器（有状态，每次请求 new 一个）
class AnthropicStreamConverter {
  constructor(model) {
    this.model = model;
    this.id = 'chatcmpl-' + Math.random().toString(36).slice(2);
    this.created = Math.floor(Date.now() / 1000);
    this.sentFirst = false;
    this.currentTool = null;   // {id,name,args}
  }
  // 输入一个 anthropic 事件对象，输出若干 openai chunk（数组）
  convert(ev) {
    const chunks = [];
    const base = () => ({ id: this.id, object: 'chat.completion.chunk', created: this.created, model: this.model });
    if (ev.type === 'message_start') {
      // 首个空 delta（OpenAI 习惯）
      chunks.push({ ...base(), choices: [{ index: 0, delta: { role: 'assistant', content: '' }, finish_reason: null }] });
      this.sentFirst = true;
    } else if (ev.type === 'content_block_start') {
      const cb = ev.content_block || {};
      if (cb.type === 'tool_use') {
        this.currentTool = { id: cb.id, name: cb.name, args: '' };
        chunks.push({ ...base(), choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: cb.id, type: 'function', function: { name: cb.name, arguments: '' } }] }, finish_reason: null }] });
      }
    } else if (ev.type === 'content_block_delta') {
      const d = ev.delta || {};
      if (d.type === 'text_delta') {
        chunks.push({ ...base(), choices: [{ index: 0, delta: { content: d.text }, finish_reason: null }] });
      } else if (d.type === 'input_json_delta' && this.currentTool) {
        this.currentTool.args += d.partial_json || '';
        chunks.push({ ...base(), choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: d.partial_json || '' } }] }, finish_reason: null }] });
      }
    } else if (ev.type === 'message_delta') {
      this.finishReason = ev.delta?.stop_reason === 'tool_use' ? 'tool_calls' : ev.delta?.stop_reason === 'max_tokens' ? 'length' : 'stop';
      this.usage = ev.usage;
    } else if (ev.type === 'message_stop') {
      const fr = this.finishReason || 'stop';
      const chunk = { ...base(), choices: [{ index: 0, delta: {}, finish_reason: fr }] };
      if (this.usage) chunk.usage = { prompt_tokens: this.usage.input_tokens ?? 0, completion_tokens: this.usage.output_tokens ?? 0, total_tokens: (this.usage.input_tokens ?? 0) + (this.usage.output_tokens ?? 0) };
      chunks.push(chunk);
    }
    return chunks;
  }
}

// ============ OpenAI Responses API ↔ Chat（客户端侧） ============

// Responses 请求 → Chat 请求
function responsesToChat(body) {
  const messages = [];
  for (const item of body.input || []) {
    if (typeof item === 'string') { messages.push({ role: 'user', content: item }); continue; }
    if (item.type === 'message' || item.role) {
      const parts = [];
      const c = item.content;
      if (typeof c === 'string') parts.push({ type: 'text', text: c });
      else if (Array.isArray(c)) for (const p of c) {
        if (p.type === 'input_text' || p.type === 'output_text') parts.push({ type: 'text', text: p.text });
        else if (p.type === 'input_image') parts.push({ type: 'image_url', image_url: { url: p.image_url } });
      }
      messages.push({ role: item.role === 'assistant' ? 'assistant' : 'user', content: parts.length === 1 && parts[0].type === 'text' ? parts[0].text : parts });
    } else if (item.type === 'function_call') {
      messages.push({ role: 'assistant', tool_calls: [{ id: item.call_id, type: 'function', function: { name: item.name, arguments: item.arguments || '{}' } }] });
    } else if (item.type === 'function_call_output') {
      messages.push({ role: 'tool', tool_call_id: item.call_id, content: typeof item.output === 'string' ? item.output : JSON.stringify(item.output) });
    }
  }
  // instructions → system
  if (body.instructions) messages.unshift({ role: 'system', content: body.instructions });
  const chat = {
    model: body.model,
    messages,
    stream: !!body.stream,
  };
  if (body.max_output_tokens) chat.max_tokens = body.max_output_tokens;
  if (body.temperature !== undefined) chat.temperature = body.temperature;
  if (body.top_p !== undefined) chat.top_p = body.top_p;
  if (Array.isArray(body.tools)) {
    chat.tools = body.tools.filter(t => t.type === 'function').map(t => ({ type: 'function', function: { name: t.name, description: t.description || '', parameters: t.parameters || { type: 'object', properties: {} } } }));
  }
  return chat;
}

// Chat 非流式响应 → Responses 格式
function chatToResponses(json) {
  const msg = json.choices?.[0]?.message || {};
  const output = [];
  if (msg.tool_calls) {
    for (const tc of msg.tool_calls) {
      output.push({ type: 'function_call', id: 'fc_' + Math.random().toString(36).slice(2), call_id: tc.id, name: tc.function?.name, arguments: tc.function?.arguments || '{}' });
    }
  }
  if (msg.content) {
    output.push({ type: 'message', id: 'msg_' + Math.random().toString(36).slice(2), role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: msg.content, annotations: [] }] });
  }
  return {
    id: 'resp_' + (json.id || Math.random().toString(36).slice(2)),
    object: 'response',
    created_at: json.created || Math.floor(Date.now() / 1000),
    status: 'completed',
    model: json.model,
    output,
    usage: {
      input_tokens: json.usage?.prompt_tokens ?? 0,
      output_tokens: json.usage?.completion_tokens ?? 0,
      total_tokens: json.usage?.total_tokens ?? 0,
    },
  };
}

// Chat SSE chunk → Responses SSE 事件的转换器
class ChatToResponsesStream {
  constructor(model) {
    this.id = 'resp_' + Math.random().toString(36).slice(2);
    this.model = model;
    this.text = '';
    this.toolCalls = {};
  }
  // 输入 openai chunk，输出 responses 事件数组（{event,data} 形式再序列化）
  convert(chunk) {
    const events = [];
    if (!this.started) {
      this.started = true;
      events.push({ type: 'response.created', response: { id: this.id, object: 'response', status: 'in_progress', model: this.model, output: [] } });
    }
    const delta = chunk.choices?.[0]?.delta || {};
    if (delta.content) {
      if (!this.textItem) {
        this.textItem = 'msg_' + Math.random().toString(36).slice(2);
        events.push({ type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: this.textItem, role: 'assistant', status: 'in_progress', content: [] } });
        events.push({ type: 'response.content_part.added', item_id: this.textItem, output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } });
      }
      this.text += delta.content;
      events.push({ type: 'response.output_text.delta', item_id: this.textItem, output_index: 0, content_index: 0, delta: delta.content });
    }
    if (delta.tool_calls) {
      for (const tc of delta.tool_calls) {
        const idx = tc.index ?? 0;
        if (!this.toolCalls[idx]) this.toolCalls[idx] = { name: '', arguments: '', id: '' };
        if (tc.function?.name) this.toolCalls[idx].name = tc.function.name;
        if (tc.id) this.toolCalls[idx].id = tc.id;
        this.toolCalls[idx].arguments += tc.function?.arguments || '';
      }
    }
    if (chunk.choices?.[0]?.finish_reason) {
      const output = [];
      const tools = Object.values(this.toolCalls);
      for (const t of tools) {
        const fcId = 'fc_' + Math.random().toString(36).slice(2);
        events.push({ type: 'response.output_item.added', output_index: 1 + Object.keys(this.toolCalls).indexOf(String(t.id)) , item: { type: 'function_call', id: fcId, call_id: t.id, name: t.name, arguments: '', status: 'in_progress' } });
        events.push({ type: 'response.output_item.done', output_index: 1 + Object.keys(this.toolCalls).indexOf(String(t.id)), item: { type: 'function_call', id: fcId, call_id: t.id, name: t.name, arguments: t.arguments || '{}', status: 'completed' } });
        output.push({ type: 'function_call', id: fcId, call_id: t.id, name: t.name, arguments: t.arguments || '{}' });
      }
      if (this.text) {
        const msgId = this.textItem || ('msg_' + Math.random().toString(36).slice(2));
        if (!this.textItem) {
          events.push({ type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: msgId, role: 'assistant', status: 'in_progress', content: [] } });
          events.push({ type: 'response.content_part.added', item_id: msgId, output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } });
        }
        events.push({ type: 'response.output_text.done', item_id: msgId, output_index: 0, content_index: 0, text: this.text });
        events.push({ type: 'response.content_part.done', item_id: msgId, output_index: 0, content_index: 0, part: { type: 'output_text', text: this.text, annotations: [] } });
        events.push({ type: 'response.output_item.done', output_index: 0, item: { type: 'message', id: msgId, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: this.text, annotations: [] }] } });
        output.push({ type: 'message', id: msgId, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: this.text, annotations: [] }] });
      }
      events.push({ type: 'response.completed', response: { id: this.id, object: 'response', status: 'completed', model: this.model, output, usage: chunk.usage ? { input_tokens: chunk.usage.prompt_tokens ?? 0, output_tokens: chunk.usage.completion_tokens ?? 0, total_tokens: chunk.usage.total_tokens ?? 0 } : undefined } });
    }
    return events;
  }
}

function partsText(content) {
  if (Array.isArray(content)) return content.map(p => p.text || '').join('');
  return '';
}
function safeParse(s) { try { return JSON.parse(s); } catch { return {}; } }

module.exports = {
  openaiToAnthropic, anthropicToOpenai, AnthropicStreamConverter,
  responsesToChat, chatToResponses, ChatToResponsesStream,
};
