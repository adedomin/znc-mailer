/*
 * Copyright (c) 2021 Anthony DeDominic <adedomin@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

// ZNC Mailer Plugin
// Based on:
/**
 * ZNC Cmd Notify
 *
 * Fowards a notify to a command of your choice
 *
 * Forked credits:
 * Copyright (c) 2011 John Reese
 * Licensed under the MIT license
 */

#include <map>
#include <string>
#include <thread>
#include <utility>

#include "boost/circular_buffer.hpp"

#include "znc/Chan.h"
#include "znc/IRCNetwork.h"
#include "znc/Modules.h"
#include "znc/User.h"
#include "znc/znc.h"

#include "time.h"

#include "sys/wait.h"

#include "curl/curl.h"

using std::string;

#if (!defined(VERSION_MAJOR) || !defined(VERSION_MINOR) || (VERSION_MAJOR == 0 && VERSION_MINOR < 207))
#error This module needs ZNC 0.207 or newer.
#endif

#define mailer_DEBUG 0

// Debug output
#if mailer_DEBUG
#define PutDebug(s) PutModule(s)
#else
#define PutDebug(s) // s
#endif


#define CTX_SIZE 10

struct curl_reader_data
{
    size_t cursor;
    std::string data;

    curl_reader_data(std::string &&body) : cursor(0), data(body)
    {
    }
};

static size_t curl_reader(char *read_dest, size_t size_dest, size_t num_items, void *myctx)
{
    auto email_body = (curl_reader_data *)myctx;
    const size_t read_dest_max = size_dest * num_items;

    if (read_dest_max < 1)
    {
        return 0;
    }
    else if (email_body->cursor < email_body->data.length())
    {
        const size_t offset = email_body->cursor;
        const size_t max_len = email_body->data.length() - offset;
        const size_t read_len = read_dest_max < max_len ? read_dest_max : max_len;
        const char *data = email_body->data.c_str() + offset;
        memcpy(read_dest, data, read_len);
        email_body->cursor += read_len;
        return read_len;
    }
    else
        return 0;
}

class CMailerMod : public CModule
{
  protected:
    // Application name
    CString app;

    // Time last notification was sent for a given context
    std::unordered_map<CString, unsigned int> last_notification_time;

    // Time of last message by user to a given context
    std::unordered_map<CString, unsigned int> last_reply_time;

    // Time of last activity by user for a given context
    std::unordered_map<CString, unsigned int> last_active_time;

    // Context for a given channel/nick conversation
    std::unordered_map<CString, std::shared_ptr<boost::circular_buffer<CString>>> msg_context;

    // Time of last activity by user in any context
    unsigned int idle_time;

    // User object
    CUser *user;

    // Network object
    CIRCNetwork *network;

    // Configuration options
    MCString options;
    MCString defaults;

  public:
    MODCONSTRUCTOR(CMailerMod)
    {
        app = "ZNC-Mailer";

        idle_time = time(NULL);

        // Current user
        user = GetUser();
        network = GetNetwork();

        // Condition language. TODO: consider removing this.
        defaults["channel_conditions"] = "all";
        defaults["query_conditions"] = "all";

        // Notification conditions
        defaults["away_only"] = "no";
        defaults["client_count_less_than"] = "1";
        defaults["highlight"] = "";
        defaults["highlight_suffix"] = " :;,";
        defaults["idle"] = "0";
        defaults["last_active"] = "0";
        defaults["last_notification"] = "0";
        defaults["nick_blacklist"] = "";
        defaults["replied"] = "no";

        // Notification Settings
        defaults["address_to"] = "<root@localhost>";
        defaults["address_from"] = "<znc@localhost>";
        defaults["smtp_server_url"] = "smtp://localhost:25";
        // SMTP Auth
        defaults["smtp_username"] = "";
        defaults["smtp_password"] = "";
    }

    virtual ~CMailerMod()
    {
    }

  protected:
    /**
     * Helper to Get the Circular Buffer Message Context for a given Context (channel, user).
     *
     * @param context A channel or user we want the message context for.
     */
    std::shared_ptr<boost::circular_buffer<CString>>
    get_notification_ctx(const CString &context="*mailer")
    {
        std::shared_ptr<boost::circular_buffer<CString>> ctx_buf = nullptr;
        if (msg_context.find(context) == msg_context.end())
        {
            auto new_ctx = std::make_shared<boost::circular_buffer<CString>>(CTX_SIZE);
            auto res = msg_context.insert({context, new_ctx});
            if (res.second)
            {
                ctx_buf = res.first->second;
            }
            else
            {
                PutDebug("[warning] Failed to add a context buffer for: " + context);
            }
        }
        else {
            ctx_buf = msg_context[context];
        }

        return ctx_buf;
    }

    CString get_local_time_str(const char *format)
    {
        const time_t now = time(nullptr);
        struct tm timeinfo = {};

        localtime_r(&now, &timeinfo);

        // just to be safe.
        char date_time[128] = {};
        const size_t len = strftime(date_time, sizeof(date_time), format, &timeinfo);
        return CString(date_time, len);
    }

    void add_message_ctx(const CString &context, const CString &nick, const CString &msg)
    {
        auto msg_ctx = get_notification_ctx(context);
        if (msg_ctx != nullptr)
        {
            CString mesg = get_local_time_str("[%Y-%m-%d %T%z]");
            mesg += " <" + nick + "> " + msg;
            msg_ctx->push_back(mesg);
        }
    }

    /**
     * Send a message to the currently-configured email.
     * Requires (and assumes) that the user has already configured their
     * username and API secret using the 'set' command.
     *
     * @param message Message to be sent to the user
     * @param context Channel or nick context
     * @param from_nick The nickname who sent the message
     */
    bool send_message(const CString &message,
                      const CString &context = "*mailer",
                      const CString &from_nick = "*mailer")
    {
        auto ctx_buf = get_notification_ctx(context);

        auto ctx_body = CString();
        if (ctx_buf != nullptr) {
            for (const CString &msg : *ctx_buf)
            {
                ctx_body += msg + "\r\n";
            }
        }

        CString date_time = get_local_time_str("%a, %d %b %Y %T %z (%Z)");

        // Email config.
        CString to = options["address_to"];
        CString from = options["address_from"];
        CString smtp_server = options["smtp_server_url"];
        CString username = options["smtp_username"];
        CString password = options["smtp_password"];

        std::thread mailer_task([=]()->void {
            CURL *curl = curl_easy_init();
            if (curl)
            {
                curl_easy_setopt(curl, CURLOPT_URL, smtp_server.c_str());
                curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from.c_str());
                if (username.length() != 0 && password.length() != 0)
                {
                    curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
                    curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
                }

                struct curl_slist *recipients = nullptr;
                recipients = curl_slist_append(recipients, to.c_str());
                curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

                std::stringstream body;
                body << "To: " << to << "\r\n"
                     << "From: " << from << "\r\n"
                     << "Date: " << date_time << "\r\n"
                     << "Subject: "
                         << network->GetName() << " - "
                         << context << " from " << from_nick << "\r\n"
                     << "\r\n"
                     << "Message: " << message << "\r\n"
                     << "Context:\r\n"
                     << ctx_body;
                auto email_body = curl_reader_data(body.str());
                curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_reader);
                curl_easy_setopt(curl, CURLOPT_READDATA, &email_body);
                curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
                auto res = curl_easy_perform(curl);

                if (res != CURLE_OK)
                {
                    auto emsg = std::string(curl_easy_strerror(res));
                    PutModule("[error] Could not send email: " + emsg);
                }
                curl_slist_free_all(recipients);
                curl_easy_cleanup(curl);
            }
            else
            {
                PutModule("[error] Could not send email: could not init curl.");
            }
        });
        mailer_task.detach();

        return true;
    }

    /**
     * Evaluate a boolean expression using condition values.
     * All tokens must be separated by spaces, using "and" and "or" for
     * boolean operators, "(" and ")" to enclose sub-expressions, and
     * condition option names to evaluate each condition.
     *
     * @param expression Boolean expression string
     * @param context Notification context
     * @param nick Sender nick
     * @param message Message contents
     * @return Result of boolean evaluation
     */
    bool eval(const CString &expression, const CString &context = CString(""), const CNick &nick = CNick(""),
              const CString &message = " ")
    {
        CString padded = expression.Replace_n("(", " ( ");
        padded.Replace(")", " ) ");

        VCString tokens;
        padded.Split(" ", tokens, false);

        PutDebug("Evaluating message: <" + nick.GetNick() + "> " + message);
        bool result = eval_tokens(tokens.begin(), tokens.end(), context, nick, message);

        return result;
    }

#define expr(x, y)                                                                                                     \
    else if (token == x)                                                                                               \
    {                                                                                                                  \
        bool result = y;                                                                                               \
        dbg += CString(x) + "/" + CString(result ? "true" : "false") + " ";                                            \
        value = oper ? value && result : value || result;                                                              \
    }

    /**
     * Evaluate a tokenized boolean expression, or sub-expression.
     *
     * @param pos Token vector iterator current position
     * @param end Token vector iterator end position
     * @param context Notification context
     * @param nick Sender nick
     * @param message Message contents
     * @return Result of boolean expression
     */
    bool eval_tokens(VCString::iterator pos, VCString::iterator end, const CString &context, const CNick &nick,
                     const CString &message)
    {
        bool oper = true;
        bool value = true;

        CString dbg = "";

        for (; pos != end; pos++)
        {
            CString token = pos->AsLower();

            if (token == "(")
            {
                // recursively evaluate sub-expressions
                bool inner = eval_tokens(++pos, end, context, nick, message);
                dbg += "( inner/" + CString(inner ? "true" : "false") + " ) ";
                value = oper ? value && inner : value || inner;

                // search ahead to the matching parenthesis token
                unsigned int parens = 1;
                while (pos != end)
                {
                    if (*pos == "(")
                    {
                        parens++;
                    }
                    else if (*pos == ")")
                    {
                        parens--;
                    }

                    if (parens == 0)
                    {
                        break;
                    }

                    pos++;
                }
            }
            else if (token == ")")
            {
                pos++;
                PutDebug(dbg);
                return value;
            }
            else if (token == "and")
            {
                dbg += "and ";
                oper = true;
            }
            else if (token == "or")
            {
                dbg += "or ";
                oper = false;
            }

            expr("true", true) expr("false", false) expr("away_only", away_only())
                expr("client_count_less_than", client_count_less_than()) expr("highlight", highlight(message))
                    expr("idle", idle()) expr("last_active", last_active(context))
                        expr("last_notification", last_notification(context))
                            expr("nick_blacklist", nick_blacklist(nick)) expr("replied", replied(context))

                                else
            {
                PutModule("Error: Unexpected token \"" + token + "\"");
            }
        }

        PutDebug(dbg);
        return value;
    }

#undef expr

  protected:
    /**
     * Check if the away status condition is met.
     *
     * @return True if away_only is not "yes" or away status is set
     */
    bool away_only()
    {
        CString value = options["away_only"].AsLower();
        return value != "yes" || network->IsIRCAway();
    }

    /**
     * Check how many clients are connected to ZNC.
     *
     * @return Number of connected clients
     */
    unsigned int client_count()
    {
        return network->GetClients().size();
    }

    /**
     * Check if the client_count condition is met.
     *
     * @return True if client_count is less than client_count_less_than or if client_count_less_than is zero
     */
    bool client_count_less_than()
    {
        unsigned int value = options["client_count_less_than"].ToUInt();
        return value == 0 || client_count() < value;
    }

    /**
     * Determine if the given message matches any highlight rules.
     *
     * @param message Message contents
     * @return True if message matches a highlight
     */
    bool highlight(const CString &message)
    {
        CString msg = " " + message.AsLower() + " ";

        VCString values;
        options["highlight"].Split(" ", values, false);

        for (const CString &hl : values)
        {
            CString value = hl.AsLower();
            char prefix = value[0];
            bool notify = true;

            if (prefix == '-')
            {
                notify = false;
                value.LeftChomp(1);
            }
            else if (prefix == '_')
            {
                value = " " + value.LeftChomp_n(1) + " ";
            }

            value = "*" + value + "*";

            if (msg.WildCmp(value))
            {
                return notify;
            }
        }

        auto suffix = options["highlight_suffix"];
        CString nick = network->GetIRCNick().GetNick();

        if (suffix.length() != 0) {
            for (const char &s: suffix)
            {
                auto concat = nick+s;
                if (message.find(concat) != string::npos)
                    return true;
            }
            return false;
        }
        else if (message.find(nick) != string::npos)
        {
            return true;
        }
        else
            return false;
    }

    /**
     * Check if the idle condition is met.
     *
     * @return True if idle is zero or elapsed time is greater than idle
     */
    bool idle()
    {
        unsigned int value = options["idle"].ToUInt();
        unsigned int now = time(NULL);
        return value == 0 || idle_time + value < now;
    }

    /**
     * Check if the last_active condition is met.
     *
     * @param context Channel or nick context
     * @return True if last_active is zero or elapsed time is greater than last_active
     */
    bool last_active(const CString &context)
    {
        unsigned int value = options["last_active"].ToUInt();
        unsigned int now = time(NULL);
        return value == 0 || last_active_time.count(context) < 1 || last_active_time[context] + value < now;
    }

    /**
     * Check if the last_notification condition is met.
     *
     * @param context Channel or nick context
     * @return True if last_notification is zero or elapsed time is greater than last_nofication
     */
    bool last_notification(const CString &context)
    {
        unsigned int value = options["last_notification"].ToUInt();
        unsigned int now = time(NULL);
        return value == 0 || last_notification_time.count(context) < 1 || last_notification_time[context] + value < now;
    }

    /**
     * Check if the nick_blacklist condition is met.
     *
     * @param nick Nick that sent the message
     * @return True if nick is not in the blacklist
     */
    bool nick_blacklist(const CNick &nick)
    {
        VCString blacklist;
        options["nick_blacklist"].Split(" ", blacklist, false);

        CString name = nick.GetNick().AsLower();

        for (const auto &ignore : blacklist)
        {
            if (name.WildCmp(ignore.AsLower()))
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the replied condition is met.
     *
     * @param context Channel or nick context
     * @return True if last_reply_time > last_notification_time or if replied is not "yes"
     */
    bool replied(const CString &context)
    {
        CString value = options["replied"].AsLower();
        return value != "yes" || last_notification_time[context] == 0 ||
               last_notification_time[context] < last_reply_time[context];
    }

    /**
     * Determine when to notify the user of a channel message.
     *
     * @param nick Nick that sent the message
     * @param channel Channel the message was sent to
     * @param message Message contents
     * @return Notification should be sent
     */
    bool notify_channel(const CNick &nick, const CChan &channel, const CString &message)
    {
        CString context = channel.GetName();

        CString expression = options["channel_conditions"].AsLower();
        if (expression != "all")
        {
            return eval(expression, context, nick, message);
        }

        return away_only() && client_count_less_than() && highlight(message) && idle() && last_active(context) &&
               last_notification(context) && nick_blacklist(nick) && replied(context) && true;
    }

    /**
     * Determine when to notify the user of a private message.
     *
     * @param nick Nick that sent the message
     * @return Notification should be sent
     */
    bool notify_pm(const CNick &nick, const CString &message)
    {
        CString context = nick.GetNick();

        CString expression = options["query_conditions"].AsLower();
        if (expression != "all")
        {
            return eval(expression, context, nick, message);
        }

        return away_only() && client_count_less_than() && idle() && last_active(context) &&
               last_notification(context) && nick_blacklist(nick) && replied(context) && true;
    }

  protected:
    /**
     * Handle the plugin being loaded.  Retrieve plugin config values.
     *
     * @param args Plugin arguments
     * @param message Message to show the user after loading
     */
    bool OnLoad(const CString &args, CString &message)
    {
        for (const auto &[key, value] : defaults)
        {
            CString user_value = GetNV(key);
            options[key] = user_value == "" ? value : user_value;
        }

        return true;
    }

    /**
     * Handle channel messages.
     *
     * @param nick Nick that sent the message
     * @param channel Channel the message was sent to
     * @param message Message contents
     */
    EModRet OnChanMsg(CNick &nick, CChan &channel, CString &message)
    {
        add_message_ctx(channel.GetName(), nick.GetNick(), message);
        if (notify_channel(nick, channel, message))
        {
            CString msg = "";
            auto nickname = nick.GetNick();
            msg += "<" + nickname;
            msg += "> " + message;

            send_message(msg, channel.GetName(), nickname);
        }

        return CONTINUE;
    }

    /**
     * Handle channel actions.
     *
     * @param nick Nick that sent the action
     * @param channel Channel the message was sent to
     * @param message Message contents
     */
    EModRet OnChanAction(CNick &nick, CChan &channel, CString &message)
    {
        add_message_ctx(channel.GetName(), nick.GetNick(), message);
        if (notify_channel(nick, channel, message))
        {
            CString msg = "";
            auto nickname = nick.GetNick();
            msg += "<" + nickname;
            msg += "> " + message;

            send_message(msg, channel.GetName(), nickname);
        }

        return CONTINUE;
    }

    /**
     * Handle a private message.
     *
     * @param nick Nick that sent the message
     * @param message Message contents
     */
    EModRet OnPrivMsg(CNick &nick, CString &message)
    {
        add_message_ctx(nick.GetNick(), nick.GetNick(), message);
        if (notify_pm(nick, message))
        {
            CString msg = "<" + nick.GetNick();
            msg += "> " + message;

            bool sent = send_message(msg, nick.GetNick(), nick.GetNick());

            if (sent)
            {
                PutIRC("PRIVMSG " + nick.GetNick() + " : [znc] User not connected. Notification message sent.");
            }
            else
            {
                PutIRC("PRIVMSG " + nick.GetNick() +
                       " : [znc] User not connected. Notification message failed to send.");
            }
        }

        return CONTINUE;
    }

    /**
     * Handle a private action.
     *
     * @param nick Nick that sent the action
     * @param message Message contents
     */
    EModRet OnPrivAction(CNick &nick, CString &message)
    {
        return OnPrivMsg(nick, message);
    }

    /**
     * Handle a message sent by the user.
     *
     * @param target Target channel or nick
     * @param message Message contents
     */
    EModRet OnUserMsg(CString &target, CString &message)
    {
        last_reply_time[target] = last_active_time[target] = idle_time = time(NULL);
        return CONTINUE;
    }

    /**
     * Handle an action sent by the user.
     *
     * @param target Target channel or nick
     * @param message Message contents
     */
    EModRet OnUserAction(CString &target, CString &message)
    {
        last_reply_time[target] = last_active_time[target] = idle_time = time(NULL);
        return CONTINUE;
    }

    /**
     * Handle the user joining a channel.
     *
     * @param channel Channel name
     * @param key Channel key
     */
    EModRet OnUserJoin(CString &channel, CString &key)
    {
        idle_time = time(NULL);
        return CONTINUE;
    }

    /**
     * Handle the user parting a channel.
     *
     * @param channel Channel name
     * @param message Part message
     */
    EModRet OnUserPart(CString &channel, CString &message)
    {
        idle_time = time(NULL);
        return CONTINUE;
    }

    /**
     * Handle the user setting the channel topic.
     *
     * @param channel Channel name
     * @param topic Topic message
     */
    EModRet OnUserTopic(CString &channel, CString &topic)
    {
        idle_time = time(NULL);
        return CONTINUE;
    }

    /**
     * Handle the user requesting the channel topic.
     *
     * @param channel Channel name
     */
    EModRet OnUserTopicRequest(CString &channel)
    {
        idle_time = time(NULL);
        return CONTINUE;
    }

    /**
     * Handle direct commands to the *mailer virtual user.
     *
     * @param command Command string
     */
    void OnModCommand(const CString &command)
    {
        VCString tokens;
        int token_count = command.Split(" ", tokens, false);

        if (token_count < 1)
        {
            return;
        }

        CString action = tokens[0].AsLower();

        // SET command
        if (action == "set")
        {
            if (token_count < 3)
            {
                PutModule("Usage: set <option> <value>");
                return;
            }

            CString option = tokens[1].AsLower();
            CString value = command.Token(2, true, " ");
            MCString::iterator pos = options.find(option);

            if (pos == options.end())
            {
                PutModule("Error: invalid option name");
            }
            else
            {
                if (option == "channel_conditions" || option == "query_conditions")
                {
                    if (value != "all")
                    {
                        eval(value);
                    }
                }

                options[option] = value;
                options[option].Trim();
                SetNV(option, options[option]);
            }
        }
        // APPEND command
        else if (action == "append")
        {
            if (token_count < 3)
            {
                PutModule("Usage: append <option> <value>");
                return;
            }

            CString option = tokens[1].AsLower();
            CString value = command.Token(2, true, " ");
            MCString::iterator pos = options.find(option);

            if (pos == options.end())
            {
                PutModule("Error: invalid option name");
            }
            else
            {
                options[option] += " " + value;
                options[option].Trim();
                SetNV(option, options[option]);
            }
        }
        // PREPEND command
        else if (action == "prepend")
        {
            if (token_count < 3)
            {
                PutModule("Usage: prepend <option> <value>");
                return;
            }

            CString option = tokens[1].AsLower();
            CString value = command.Token(2, true, " ");
            MCString::iterator pos = options.find(option);

            if (pos == options.end())
            {
                PutModule("Error: invalid option name");
            }
            else
            {
                options[option] = value + " " + options[option];
                options[option].Trim();
                SetNV(option, options[option]);
            }
        }
        // UNSET command
        else if (action == "unset")
        {
            if (token_count != 2)
            {
                PutModule("Usage: unset <option>");
                return;
            }

            CString option = tokens[1].AsLower();
            MCString::iterator pos = options.find(option);

            if (pos == options.end())
            {
                PutModule("Error: invalid option name");
            }
            else
            {
                options[option] = defaults[option];
                DelNV(option);
            }
        }
        // GET command
        else if (action == "get")
        {
            if (token_count > 2)
            {
                PutModule("Usage: get [<option>]");
                return;
            }

            if (token_count < 2)
            {
                CTable table;

                table.AddColumn("Option");
                table.AddColumn("Value");

                for (const auto &[key, value] : options)
                {
                    table.AddRow();
                    table.SetCell("Option", key);
                    table.SetCell("Value",  value);
                }

                PutModule(table);
                return;
            }

            CString option = tokens[1].AsLower();
            MCString::iterator pos = options.find(option);

            if (pos == options.end())
            {
                PutModule("Error: invalid option name");
            }
            else
            {
                PutModule(option + CString(": \"") + options[option] + CString("\""));
            }
        }
        // STATUS command
        else if (action == "status")
        {
            CTable table;

            table.AddColumn("Condition");
            table.AddColumn("Status");

            table.AddRow();
            table.SetCell("Condition", "away");
            table.SetCell("Status", network->IsIRCAway() ? "yes" : "no");

            table.AddRow();
            table.SetCell("Condition", "client_count");
            table.SetCell("Status", CString(client_count()));

            unsigned int now = time(NULL);
            unsigned int ago = now - idle_time;

            table.AddRow();
            table.SetCell("Condition", "idle");
            table.SetCell("Status", CString(ago) + " seconds");

            if (token_count > 1)
            {
                CString context = tokens[1];

                table.AddRow();
                table.SetCell("Condition", "last_active");

                if (last_active_time.count(context) < 1)
                {
                    table.SetCell("Status", "n/a");
                }
                else
                {
                    ago = now - last_active_time[context];
                    table.SetCell("Status", CString(ago) + " seconds");
                }

                table.AddRow();
                table.SetCell("Condition", "last_notification");

                if (last_notification_time.count(context) < 1)
                {
                    table.SetCell("Status", "n/a");
                }
                else
                {
                    ago = now - last_notification_time[context];
                    table.SetCell("Status", CString(ago) + " seconds");
                }

                table.AddRow();
                table.SetCell("Condition", "replied");
                table.SetCell("Status", replied(context) ? "yes" : "no");
            }

            PutModule(table);
        }
        // SEND command
        else if (action == "send")
        {
            CString message = command.Token(1, true, " ", true);
            add_message_ctx("*mailer", "*mailer", message);
            send_message(message, "*mailer", "*mailer");
        }
        else if (action == "test-hl")
        {
            CString message = command.Token(1, true, " ", true);
            if (highlight(message))
            {
                PutModule("Would Email.");
            }
            else
            {
                PutModule("No Match.");
            }
        }
        // HELP command
        else if (action == "help")
        {
            PutModule("To be written.");
        }
        // EVAL command
        else if (action == "eval")
        {
            CString value = command.Token(1, true, " ");
            PutModule(eval(value) ? "true" : "false");
        }
        else
        {
            PutModule("Error: invalid command, try `help`");
        }
    }
};

MODULEDEFS(CMailerMod, "Send highlights and personal messages to a given E-Mail address.")
