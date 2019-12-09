package com.Nusstudios.Instarchiver;

import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainController {
    public Button btn_unfollow;
    public Button btn_follow;
    public Button btn_update;
    public Button btn_check;
    public CheckBox chkb_ddv;
    public CheckBox chkb_login;
    public ComboBox cb_users;
    public TextField tf_usertofollow;
    public TextField tf_usr;
    public PasswordField pf_pwd;
    public Label lbl_status;
    public static Task task;
    public static HttpURLConnection conn;
    public static InputStream is;
    public static int read;
    public static byte[] buffer;
    public static ByteArrayOutputStream baos;
    public static Stage stage;

    @FXML
    protected void initialize() throws Exception {
        UPDT(false);
    }

    public void check() throws Exception {
        UPDT(true);
    }

    public void UPDT(boolean chk) throws Exception {
        getPreferences();
        updateFollowing(chk);
    }

    public void getPreferences() throws Exception {
        String dir = System.getProperty("user.dir");
        String fn = dir + File.separator + "instarchiverPreferences.json";

        if (new File(fn).exists()) {
            cb_users.getItems().clear();
            FileInputStream f = new FileInputStream(fn);
            byte[] buff = new byte[f.available()];
            f.read(buff);
            f.close();
            String content = new String(buff, "UTF-8");
            JSONObject prefs = new JSONObject(cryptText(content));

            if (prefs.has("following")) {
                JSONArray following = prefs.getJSONArray("following");
                boolean dualDownloadCheck = prefs.getBoolean("dual download check");
                chkb_ddv.setDisable(!dualDownloadCheck);
                boolean log_in = prefs.getBoolean("log in");

                if (log_in) {
                    chkb_login.setSelected(true);

                    JSONObject login = prefs.getJSONObject("login");
                    String username = login.getString("username");
                    String password = login.getString("password");
                    tf_usr.setText(username);
                    pf_pwd.setText(password);
                }
                else {
                    chkb_login.setSelected(false);
                }

                for (int i = 0; i < following.length(); i++) {
                    String username = following.getString(i);
                    cb_users.getItems().add(username);
                }
            }

            chkb_ddv.setDisable(!prefs.getBoolean("dual download check"));
        }
    }

    // key value pairs form the key, loners form the value
    public Map.Entry<Map<String, String>, List<String>> serializeCookies(String cookies) {
        String[] keyValuePairs = cookies.split(";\\s");
        Map<String, String> parsedKeyValuePairs = new HashMap<>();
        List<String> loners = new ArrayList<>();

        for (String keyValuePair : keyValuePairs) {
            if (keyValuePair.contains("=")) {
                String[] array = keyValuePair.split("=");
                String key = array[0];
                String value = array[1];
                parsedKeyValuePairs.put(key, value);
            }
            else {
                loners.add(keyValuePair);
            }
        }


        return new AbstractMap.SimpleEntry<>(parsedKeyValuePairs, loners);
    }

    public String extendCookie(String cookie, String key, String value) {
        if (cookie.length() != 0) {
            cookie += "; ";
        }

        cookie += key + "=" + value;
        return cookie;
    }

    public String getLoginCookies(String username, String password) throws Exception {
        Map<String, String> heads = new HashMap<>();
        String loginPage = downloadStringWithHeaders("https://www.instagram.com/accounts/login/", heads).getKey();
        Pattern ptrn = Pattern.compile("window\\._sharedData\\s*=\\s*(\\{[\\u0000-\\uFFFF]*?\\});");
        Matcher mtchr = ptrn.matcher(loginPage);
        mtchr.find();
        String configuration = mtchr.group(1);
        JSONObject json = new JSONObject(configuration);
        String csrf_token = json.getJSONObject("config").getString("csrf_token");
        String rollout_hash = json.getString("rollout_hash");
        HttpURLConnection post = (HttpURLConnection)new URL("https://www.instagram.com/accounts/login/ajax/").openConnection();
        post.setRequestMethod("POST");
        JSONObject queryParams = new JSONObject();
        String postData = "username=" + username + "&password=" + password + "&queryParams=" + URLEncoder.encode(queryParams.toString(), "UTF-8") + "&optIntoOneTap=false";
        post.setRequestProperty("X-Instagram-AJAX", rollout_hash);
        post.setRequestProperty("X-CSRFToken", csrf_token);
        post.setDoOutput(true);
        DataOutputStream postDataStream = new DataOutputStream(post.getOutputStream());
        postDataStream.writeBytes(postData);
        postDataStream.flush();
        postDataStream.close();
        int code = post.getResponseCode();
        Map<String, List<String>> headers = post.getHeaderFields();

        List<String> cookies = headers.get("Set-Cookie");
        String loginCookies = "";

        for (String cookie : cookies) {
            Map<String, String> serialization = serializeCookies(cookie).getKey();

            if (serialization.containsKey("ds_user_id")) {
                loginCookies = extendCookie(loginCookies, "ds_user_id", serialization.get("ds_user_id"));
            }
            else if (serialization.containsKey("sessionid")) {
                loginCookies = extendCookie(loginCookies, "sessionid", serialization.get("sessionid"));
            }
        }

        return loginCookies;
    }

    public String unescapeJSON(String escapedJSON) {
        return escapedJSON.replaceAll("\\\"]", "");
    }

    public void updateFollowing(boolean chk) {
        disableUI();

        task = new Task() {
            @Override
            protected Object call() throws Exception {
                updateMessage("Updating started...");
                int numToUpdate = cb_users.getItems().size();
                String loginCookies = "";

                if (chkb_login.isSelected()) {
                    loginCookies = getLoginCookies(tf_usr.getText(), pf_pwd.getText());
                }

                for (int i = 0; i < numToUpdate; i++) {
                    String username = String.valueOf(cb_users.getItems().get(i));
                    Map<String, String> params = getParams(username, loginCookies, ParamType.GetPageNodes);
                    String id = params.get("id");
                    String queryId = params.get("queryId");
                    String rhxgis = params.get("rhxgis");
                    updateMessage("Updating " + (i + 1) + " of " + numToUpdate + "...");
                    int reqNum = 0;
                    int processed = 0;
                    int count = -1;
                    String end_cursor = null;

                    mainLoop:
                    while (true) {
                        JSONObject pageNodes = new JSONObject();

                        if (chkb_login.isSelected()) {
                            pageNodes = getPageNodesWithCookies(loginCookies, rhxgis, id, queryId, reqNum, end_cursor);
                        }
                        else {
                            pageNodes = getPageNodes(rhxgis, id, queryId, reqNum, end_cursor);
                        }

                        JSONObject edge_owner_to_timeline_media = pageNodes.getJSONObject("data").getJSONObject("user").getJSONObject("edge_owner_to_timeline_media");
                        JSONObject page_info = edge_owner_to_timeline_media.getJSONObject("page_info");
                        boolean has_next_page = page_info.getBoolean("has_next_page");

                        // To be written 1 time only
                        if (count == -1) {
                            count = edge_owner_to_timeline_media.getInt("count");
                        }

                        JSONArray edges = new JSONArray();

                        if (reqNum != 0) {
                            edges = edge_owner_to_timeline_media.getJSONArray("edges");
                            end_cursor = page_info.optString("end_cursor");
                        }

                        if (count == 0) {
                            break mainLoop;
                        }

                        File rootF = new File(System.getProperty("user.dir") + File.separator + username);
                        File root2F = new File(rootF.getPath() + File.separator + "Archive");

                        if (!rootF.exists()) {
                            rootF.mkdir();
                            root2F.mkdir();
                        }

                        for (int x = 0; x < edges.length(); x++) {
                            JSONObject edge = edges.getJSONObject(x);
                            JSONObject node = edge.getJSONObject("node");
                            BigInteger nodeId = node.getBigInteger("id");
                            String __typename = node.getString("__typename");
                            File nodeF = new File(root2F.getPath() + File.separator + nodeId);
	                        String shortcode = node.getString("shortcode");
                            JSONObject shortcodeNodes = new JSONObject();

                            if (chkb_login.isSelected()) {
                                shortcodeNodes = getShortcodeNodesWithCookies(shortcode, loginCookies);
                            }
                            else {
                                shortcodeNodes = getShortcodeNodes(shortcode);
                            }

                            if (!shortcodeNodes.has("graphql")) {
                                shortcodeNodes = new JSONObject(unescapeJSON(shortcodeNodes.getString("key")));
                            }

	                        JSONObject shortcode_media = shortcodeNodes.getJSONObject("graphql").getJSONObject("shortcode_media");
	                        String date = getDateFromShortCodeMedia(shortcode_media);

                            if (nodeF.exists()) {
                                if (!chk) {
                                    break mainLoop;
                                }
                            }
                            else {
                                nodeF.mkdir();
                                writeShortcodeMediaData(nodeF, shortcode_media);

                                if (__typename.equals("GraphImage")) {
                                    String display_url = node.getString("display_url");
                                    String media_name = getTargetFile(display_url);

                                    if (chkb_ddv.isSelected()) {
                                        doubleCheckDownloadToFile(display_url, nodeF.getPath() + File.separator + media_name);
                                    }
                                    else {
                                        downloadToFile(display_url, nodeF.getPath() + File.separator + media_name);
                                    }
                                }
                                else if (__typename.equals("GraphVideo")) {
                                    String video_url = node.getString("video_url");
                                    String media_name = getTargetFile(video_url);

                                    if (chkb_ddv.isSelected()) {
                                        doubleCheckDownloadToFile(video_url, nodeF.getPath() + File.separator + media_name);
                                    }
                                    else {
                                        downloadToFile(video_url, nodeF.getPath() + File.separator + media_name);
                                    }
                                }
                                else if (__typename.equals("GraphSidecar")) {
                                    JSONObject edge_sidecar_to_children = node.getJSONObject("edge_sidecar_to_children");
                                    JSONArray childrenEdges = edge_sidecar_to_children.getJSONArray("edges");

                                    for (int y = 0; y < childrenEdges.length(); y++) {
                                        JSONObject childEdge = childrenEdges.getJSONObject(y);
                                        JSONObject childNode = childEdge.getJSONObject("node");
                                        BigInteger childNodeId = childNode.getBigInteger("id");
                                        String display_url = childNode.getString("display_url");
                                        File childNodeF = new File(nodeF.getPath() + File.separator + childNodeId);
                                        childNodeF.mkdir();
                                        String media_name = getTargetFile(display_url);

                                        if (chkb_ddv.isSelected()) {
                                            doubleCheckDownloadToFile(display_url, nodeF.getPath() + File.separator + media_name);
                                        }
                                        else {
                                            downloadToFile(display_url, nodeF.getPath() + File.separator + media_name);
                                        }
                                    }
                                }
                                else {
                                    break mainLoop;
                                }
                            }
                        }

                        processed += reqNum;

                        if (has_next_page) {
                            int newReqNum = 12;

                            if ((count - processed) < 12 ) {
                                // newReqNum = 12; Also good.
                                newReqNum = count - processed;
                            }

                            reqNum = newReqNum;
                        }
                        else {
                            break mainLoop;
                        }

                    }
                }

                updateMessage("Finished");

                new Runnable() {
                    @Override
                    public void run() {
                        enableUI();
                    }
                }.run();

                return null;
            }
        };

        lbl_status.textProperty().bind(task.messageProperty());
        new Thread(task).start();
    }

    public enum ParamType {
        GetPageNodes,
        GetReelNodes,
        GetReelInfo
    }

    public Map<String, String> getParams(String user, String cookies, ParamType pt) throws Exception {
        BigInteger userId = null;
        Map<String, String> reqHeaders = new HashMap<>();
        reqHeaders.put("Cookie", cookies);
        AbstractMap.SimpleEntry<String, String> docAndCookies = downloadStringWithHeaders("https://instagram.com/" + user, reqHeaders);
        String doc = docAndCookies.getKey();
        List<String> jsLinkRegexes = new ArrayList<>();

        if (pt == ParamType.GetPageNodes || pt == ParamType.GetReelInfo) {
            jsLinkRegexes.add("<script.*?src\\s*=\\s*\"(\\/static\\/bundles\\/en_US_Commons\\.js\\/.*?)\"");
            jsLinkRegexes.add("<script.*?src\\s*=\\s*\"(\\/static\\/bundles\\/ConsumerCommons\\.js\\/.*?\\.js)\"");
            jsLinkRegexes.add("src\\s*=\\s*\"\\s*(.*?ProfilePageContainer\\.js\\s*\\/\\s*.*?\\.js)");
            jsLinkRegexes.add("href\\s*=\\s*\"\\s*(.*?ProfilePageContainer\\.js\\s*\\/\\s*.*?\\.js)");
        }
        else {
            jsLinkRegexes.add("href\\s*=\\s*\"\\s*(.*?Consumer\\.js\\s*\\/\\s*.*?\\.js)");
            jsLinkRegexes.add("src\\s*=\\s*\"\\s*(.*?Consumer\\.js\\s*\\/\\s*.*?\\.js)");
        }

        String jsLink = null;

        for (int i = 0; i < jsLinkRegexes.size(); i++) {
            Pattern ptrn = Pattern.compile(jsLinkRegexes.get(i));
            Matcher mtchr = ptrn.matcher(doc);

            if (mtchr.find()) {
                jsLink = mtchr.group(1);
                break;
            }
            else if (i == jsLinkRegexes.size() - 1) {
                return null;
            }
        }

        String js = downloadString("https://instagram.com" + jsLink);
        List<String> queryIdRegexes = new ArrayList<>();

        if (pt == ParamType.GetPageNodes) {
            queryIdRegexes.add(".\\s*?=\\s*?\"PROFILE_POSTS_UPDATED\"[\\u0000-\\uFFFF]*?queryId:\\s*\"(.*?)\"");
            queryIdRegexes.add("profilePosts\\s*\\.\\s*byUserId(?:(?!profilePosts)[\\u0000-\\uFFFF])*?queryId\\s*:\\s*\"(\\w*)\"");
        }
        else if (pt == ParamType.GetReelInfo) {
            queryIdRegexes.add("(?:(?:const)|(?:var))\\s+\\w+?=\\s*?\"(\\w+?)\"\\s*");
        }
        else {
            queryIdRegexes.add("(?:(?:var)|(?:const))(?:(?!(?:(?:var)|(?:const))).)+?h=\"(.+?)\"");
        }

        String queryId = null;

        for (int i = 0; i < queryIdRegexes.size(); i++) {
            Pattern ptrn = Pattern.compile(queryIdRegexes.get(i));
            Matcher mtchr = ptrn.matcher(js);

            if (mtchr.find()) {
                queryId = mtchr.group(1);
                break;
            }
            else if (i == queryIdRegexes.size() - 1) {
                queryId = "42323d64886122307be10013ad2dcc44";
                break;
            }
        }

        String rhxgis = "";
        JSONObject usro = null;
        List<String> configRegexes = new ArrayList<>();
        configRegexes.add("window\\._sharedData\\s*=\\s*(\\{[\\u0000-\\uFFFF]*?\\});");

        for (int i = 0; i < configRegexes.size(); i++) {
            Pattern ptrn = Pattern.compile(configRegexes.get(i));
            Matcher mtchr = ptrn.matcher(doc);

            if (mtchr.find()) {
                usro = new JSONObject(mtchr.group(1));
            }
            else if (i == configRegexes.size() - 1) {
                return null;
            }
        }

        BigInteger id = usro.getJSONObject("entry_data").getJSONArray("ProfilePage").getJSONObject(0).getJSONObject("graphql").getJSONObject("user").getBigInteger("id");
        userId = id;

        if (usro.has("rhx_gis"))
        {
            rhxgis = usro.getString("rhx_gis");
        }

        Map<String, String> params = new HashMap<>();
        params.put("id", userId.toString());
        params.put("queryId", queryId);
        params.put("rhxgis", rhxgis);
        return params;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    public String signature(String rhxgis, String variablesJSONStr) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest((rhxgis + ":" + variablesJSONStr).getBytes("UTF-8"));
        return bytesToHex(digest).toLowerCase();
    }

    public void doubleCheckDownloadToFile(String url, String fn) throws Exception {
        downloadToFile(url, fn + ".0");
        downloadToFile(url, fn + ".1");
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        FileInputStream fis0 = new FileInputStream(fn + ".0");
        byte[] buff0 = new byte[fis0.available()];
        fis0.read(buff0);
        fis0.close();
        FileInputStream fis1 = new FileInputStream(fn + ".1");
        byte[] buff1 = new byte[fis1.available()];
        fis1.read(buff1);
        fis1.close();
        byte[] hash0 = md.digest(buff0);
        byte[] hash1 = md.digest(buff1);
        File f1 = new File(fn + ".1");
        f1.delete();
        File f0 = new File(fn + ".0");

        if (Arrays.equals(hash0, hash1)) {
            f0.renameTo(new File(fn));
        }
        else {
        	f0.delete();
            doubleCheckDownloadToFile(url, fn);
        }
    }

    public JSONObject getReelNodesWithCookies(String cookie, String rhxgis, String queryId, JSONArray highlight_reel_ids, JSONArray reel_ids) throws Exception {
        JSONObject variables = new JSONObject();
        variables.put("reel_ids", reel_ids);
        variables.put("tag_names", new JSONArray());
        variables.put("location_ids", new JSONArray());
        variables.put("highlight_reel_ids", highlight_reel_ids);
        variables.put("include_highlight_reels", true);
        variables.put("precomposed_overlay", false);
        variables.put("show_story_viewer_list", true);
        variables.put("story_viewer_fetch_count", 50);
        variables.put("story_viewer_cursor", "");
        variables.put("stories_video_dash_manifest", false);
        Map<String, String> reqHeaders = new HashMap<>();
        reqHeaders.put("Cookie", cookie);
        reqHeaders.put("X-Instagram-GIS", signature(rhxgis, variables.toString()));

        try
        {
            return new JSONObject(downloadStringWithHeaders("https://instagram.com/graphql/query/?query_hash=" + queryId + "&variables=" + URLEncoder.encode(variables.toString(), "UTF-8"), reqHeaders).getKey());

        }
        catch (Exception ex)
        {
            return getReelNodesWithCookies(cookie, rhxgis, queryId, highlight_reel_ids, reel_ids);
        }
    }

    public JSONObject getReelInfoWithCookies(String cookie, String rhxgis, String userId, String queryId) throws Exception {
        JSONObject variables = new JSONObject();
        variables.put("user_id", userId);
        variables.put("include_chaining", false);
        variables.put("include_reel", true);
        variables.put("include_suggested_users", false);
        variables.put("include_logged_out_extras", false);
        variables.put("include_highlight_reels", true);
        Map<String, String> reqHeaders = new HashMap<>();
        reqHeaders.put("Cookie", cookie);
        reqHeaders.put("X-Instagram-GIS", signature(rhxgis, variables.toString()));

        try
        {
            return new JSONObject(downloadStringWithHeaders("https://instagram.com/graphql/query/?query_hash=" + "aec5501414615eca36a9acf075655b1e" + "&variables=" + URLEncoder.encode(variables.toString(), "UTF-8"), reqHeaders).getKey());

        }
        catch (Exception ex)
        {
            return getReelInfoWithCookies(cookie, rhxgis, userId, queryId);
        }
    }

    public JSONObject getPageNodesWithCookies(String cookie, String rhxgis, String userId, String queryId, int first, String after) throws Exception {
        JSONObject variables = new JSONObject();
        variables.put("id", userId);
        variables.put("first", first);
        Map<String, String> reqHeaders = new HashMap<>();
        reqHeaders.put("Cookie", cookie);

        if (after != null) {
            variables.put("after", after);
        }

        reqHeaders.put("X-Instagram-GIS", signature(rhxgis, variables.toString()));
        String str = "";

        try
        {
            return new JSONObject(downloadStringWithHeaders("https://instagram.com/graphql/query/?query_hash=" + queryId + "&variables=" + URLEncoder.encode(variables.toString(), "UTF-8"), reqHeaders).getKey());

        }
        catch (Exception ex)
        {
            return getPageNodes(rhxgis, userId, queryId, first, after);
        }
    }

    public JSONObject getPageNodes(String rhxgis, String userId, String queryId, int first, String after) throws Exception {
        JSONObject variables = new JSONObject();
        variables.put("id", userId);
        variables.put("first", first);
        Map<String, String> reqHeaders = new HashMap<>();

        if (after != null) {
            variables.put("after", after);
        }

        reqHeaders.put("X-Instagram-GIS", signature(rhxgis, variables.toString()));
        String str = "";

        try
        {
            return new JSONObject(downloadStringWithHeaders("https://instagram.com/graphql/query/?query_hash=" + queryId + "&variables=" + URLEncoder.encode(variables.toString(), "UTF-8"), reqHeaders).getKey());

        }
        catch (Exception ex)
        {
            return getPageNodes(rhxgis, userId, queryId, first, after);
        }
    }

    public String getDateFromShortCodeMedia(JSONObject shortcode_media) {
        long taken_at_timestamp = shortcode_media.getLong("taken_at_timestamp");
        Date date = new Date(new Timestamp(taken_at_timestamp * 1000).getTime());
        SimpleDateFormat sdf = new SimpleDateFormat();
        sdf.setTimeZone(new SimpleTimeZone(0, "GMT"));
        sdf.applyPattern("dd MMM yyyy");
        return sdf.format(date);
    }

    public void writeShortcodeMediaData(File nodeF, JSONObject shortcode_media) throws Exception {
        long taken_at_timestamp = shortcode_media.getLong("taken_at_timestamp");
        Date date = new Date(new Timestamp(taken_at_timestamp * 1000).getTime());
        SimpleDateFormat sdf = new SimpleDateFormat();
        sdf.setTimeZone(new SimpleTimeZone(0, "GMT"));
        sdf.applyPattern("dd MMM yyyy HH:mm:ss z");
        String dateStr = sdf.format(date);
        String caption = "";

        JSONArray captionEdges = shortcode_media.getJSONObject("edge_media_to_caption").getJSONArray("edges");

        if (captionEdges.length() > 0) {
            JSONObject captionNode = captionEdges.getJSONObject(0).getJSONObject("node");
            caption = captionNode.getString("text");
        }

        /* String comments = "";
        JSONArray commentEdges = shortcode_media.getJSONObject("edge_media_to_comment").getJSONArray("edges");

        for (int c = 0; c < commentEdges.length(); c++) {
            JSONObject commentNode = commentEdges.getJSONObject(c).getJSONObject("node");
            BigInteger commentId = commentNode.getBigInteger("id");
            String commentText = commentNode.getString("text");
            Long created_at = commentNode.getLong("created_at");
            Date date2 = new Date(new Timestamp(created_at * 1000).getTime());
            String date2Str = sdf.format(date2);
            String ownerUsername = commentNode.getJSONObject("owner").getString("username");
            comments += ownerUsername + " on " + date2Str + ": " + commentText + " (Comment ID: " + commentId + ")";

            if (c != commentEdges.length() - 1) {
                comments += "\n";
            }
        }

        int likeCount = shortcode_media.getJSONObject("edge_media_preview_like").getInt("count"); */
        File dataF = new File(nodeF.getPath() + File.separator + "Data.txt");
        dataF.delete();
        BufferedWriter bw = new BufferedWriter(new FileWriter(dataF.getPath()));
        bw.write("Posted: " + dateStr);
        bw.newLine();
        bw.write("Caption: " + caption);
        /* bw.newLine();

        if (!comments.equals("")) {
            bw.write(comments);
            bw.newLine();
        }

        bw.write("Likes: " + String.valueOf(likeCount)); */
        bw.flush();
        bw.close();
    }

    public JSONObject getShortcodeNodesWithCookies(String shortcode, String cookie) {
        try
        {
            Map<String, String> reqHeaders = new HashMap<>();
            reqHeaders.put("Cookie", cookie);
            return new JSONObject(downloadStringWithHeaders("https://www.instagram.com/p/" + shortcode + "/?__a=1", reqHeaders));
        }
        catch (Exception ex)
        {
            return getShortcodeNodesWithCookies(shortcode, cookie);
        }
    }

    public JSONObject getShortcodeNodes(String shortcode) throws Exception {
        try
        {
            return new JSONObject(downloadString("https://www.instagram.com/p/" + shortcode + "/?__a=1"));
        }
        catch (Exception ex)
        {
            return getShortcodeNodes(shortcode);
        }
    }

    public AbstractMap.SimpleEntry<String, String> downloadStringWithHeaders(String url, Map<String, String> reqHeaders) throws Exception {
        try {
            conn = (HttpURLConnection)new URL(url).openConnection();
            conn.setReadTimeout(20000);
            conn.setConnectTimeout(20000);
            conn.setRequestMethod("GET");

            if (reqHeaders != null) {
                for (Map.Entry<String, String> reqHeader : reqHeaders.entrySet()) {
                    conn.setRequestProperty(reqHeader.getKey(), reqHeader.getValue());
                }
            }

            conn.connect();
            Map<String, List<String>> headers = conn.getHeaderFields();
            List<String> cookies = headers.get("Set-Cookie");
            String finalCookie = "";

            if (cookies != null) {
                for (String cookie : cookies) {
                    finalCookie += "; " + cookie;
                }

                finalCookie = finalCookie.substring(2);
            }

            is = conn.getInputStream();
            buffer = new byte[26214400];
            baos = new ByteArrayOutputStream();

            while ((read = is.read(buffer)) != -1) {
                byte[] rbuffer = Arrays.copyOfRange(buffer, 0, read);
                baos.write(rbuffer);
            }

            is.close();
            String str = new String(baos.toByteArray(), "UTF-8");
            return new AbstractMap.SimpleEntry<String, String>(str, finalCookie);
        }
        catch(Exception ex) {
            return downloadStringWithHeaders(url, reqHeaders);
        }
    }

    public String downloadString(String url) throws Exception {
        try {
            conn = (HttpURLConnection)new URL(url).openConnection();
            conn.setReadTimeout(20000);
            conn.setConnectTimeout(20000);
            conn.connect();
            String str = null;

            if (conn.getResponseCode() == 200) {
                is = conn.getInputStream();
                buffer = new byte[26214400];
                baos = new ByteArrayOutputStream();

                while ((read = is.read(buffer)) != -1) {
                    byte[] rbuffer = Arrays.copyOfRange(buffer, 0, read);
                    baos.write(rbuffer);
                }

                str = new String(baos.toByteArray(), "UTF-8");
            }

            return str;
        }
        catch (Exception ex) {
            return downloadString(url);
        }
    }

    public String cryptText(String text) {
        String key = "loqirzty54u68izt77hz47hs866n298f15v";
        char[] outText = new char[text.length()];

        for (int i = 0; i < text.length(); i++) {
            outText[i] = (char)(text.charAt(i) ^ key.charAt(i % key.length()));
        }

        return new String(outText);
    }

    public void downloadToFile(String url, String path) throws Exception {
    	try {
			conn = (HttpURLConnection)new URL(url).openConnection();
            conn.setReadTimeout(20000);
            conn.setConnectTimeout(20000);
	        conn.connect();
	        is = conn.getInputStream();
	        buffer = new byte[26214400];
	        FileOutputStream fos = new FileOutputStream(path);

	        while ((read = is.read(buffer)) != -1) {
	            byte[] rbuffer = Arrays.copyOfRange(buffer,0, read);
	            fos.write(rbuffer);
	        }

	        fos.flush();
	        fos.close();
    	} 
    	catch (Exception ex) {
    		downloadToFile(url, path);
    	}
    }

    public String getTargetFile(String URL) {
        return getLastURLComponent(URL).split("\\?")[0];
    }

    public String getLastURLComponent(String URL) {
        return URL.substring(URL.lastIndexOf("/") + 1);
    }

    public void update() throws Exception {
        UPDT(false);
    }

    public void enableUI() {
        cb_users.setDisable(false);
        btn_unfollow.setDisable(false);
        tf_usertofollow.setDisable(false);
        tf_usr.setDisable(false);
        pf_pwd.setDisable(false);
        btn_follow.setDisable(false);
        btn_update.setDisable(false);
        btn_check.setDisable(false);
        chkb_ddv.setDisable(false);
        chkb_login.setDisable(false);
    }

    public void disableUI() {
        cb_users.setDisable(true);
        btn_unfollow.setDisable(true);
        tf_usertofollow.setDisable(true);
        tf_usr.setDisable(true);
        pf_pwd.setDisable(true);
        btn_follow.setDisable(true);
        btn_update.setDisable(true);
        btn_check.setDisable(true);
        chkb_ddv.setDisable(true);
        chkb_login.setDisable(true);
    }

    public void pf_pwd_keytyped() throws Exception {
        tf_usr_keytyped();
    }

    public void tf_usr_keytyped() throws Exception {
        if (chkb_login.isSelected()) {
            String dir = System.getProperty("user.dir");
            String fn = dir + File.separator + "instarchiverPreferences.json";

            if (!new File(fn).exists()) {
                createDefaultPreferences();
            }

            FileInputStream fis = new FileInputStream(fn);
            byte[] buff = new byte[fis.available()];
            fis.read(buff);
            fis.close();
            String content = new String(buff, "UTF-8");
            JSONObject prefs = new JSONObject(cryptText(content));
            prefs.remove("login");
            JSONObject login = new JSONObject();
            login.put("username", tf_usr.getText());
            login.put("password", pf_pwd.getText());
            prefs.put("login", login);
            BufferedWriter bw = new BufferedWriter(new FileWriter(fn, false));
            bw.write(cryptText(prefs.toString()));
            bw.flush();
            bw.close();
        }
    }

    public void chkb_login_statechanged() throws Exception {
        String dir = System.getProperty("user.dir");
        String fn = dir + File.separator + "instarchiverPreferences.json";

        if (!new File(fn).exists()) {
            createDefaultPreferences();
        }

        FileInputStream fis = new FileInputStream(fn);
        byte[] buff = new byte[fis.available()];
        fis.read(buff);
        fis.close();
        String content = new String(buff, "UTF-8");
        JSONObject prefs = new JSONObject(cryptText(content));
        prefs.put("log in", chkb_login.isSelected());

        if (!chkb_login.isSelected()) {
            prefs.remove("login");
        }
        else {
            JSONObject login = new JSONObject();
            login.put("username", tf_usr.getText());
            login.put("password", pf_pwd.getText());
            prefs.put("login", login);
        }

        BufferedWriter bw = new BufferedWriter(new FileWriter(fn, false));
        bw.write(cryptText(prefs.toString()));
        bw.flush();
        bw.close();
    }

    public void chkb_ddv_statechanged() throws Exception {
        String dir = System.getProperty("user.dir");
        String fn = dir + File.separator + "instarchiverPreferences.json";

        if (!new File(fn).exists()) {
            createDefaultPreferences();
        }

        FileInputStream fis = new FileInputStream(fn);
        byte[] buff = new byte[fis.available()];
        fis.read(buff);
        fis.close();
        String content = new String(buff, "UTF-8");
        JSONObject prefs = new JSONObject(cryptText(content));
        prefs.put("dual download check", chkb_ddv.isSelected());
        BufferedWriter bw = new BufferedWriter(new FileWriter(fn, false));
        bw.write(cryptText(prefs.toString()));
        bw.flush();
        bw.close();
    }

    public void createDefaultPreferences() throws Exception {
        String dir = System.getProperty("user.dir");
        String fn = dir + File.separator + "instarchiverPreferences.json";
        JSONObject prefs = new JSONObject();
        prefs.put("following", new JSONArray());
        prefs.put("dual download check", true);
        prefs.put("log in", false);
        BufferedWriter bw = new BufferedWriter(new FileWriter(fn, false));
        bw.write(cryptText(prefs.toString()));
        bw.flush();
        bw.close();
    }

    public void follow() throws Exception {
        String dir = System.getProperty("user.dir");
        String fn = dir + File.separator + "instarchiverPreferences.json";

        if (!new File(fn).exists()) {
            createDefaultPreferences();
        }

        FileInputStream fis = new FileInputStream(fn);
        byte[] buff = new byte[fis.available()];
        fis.read(buff);
        fis.close();
        String content = new String(buff, "UTF-8");
        JSONObject prefs = new JSONObject(cryptText(content));
        JSONArray following = prefs.getJSONArray("following");
        String usertofollow = tf_usertofollow.getText();
        following.put(usertofollow);
        cb_users.getItems().add(usertofollow);
        prefs.put("following", following);
        BufferedWriter bw = new BufferedWriter(new FileWriter(fn, false));
        bw.write(cryptText(prefs.toString()));
        bw.flush();
        bw.close();
        UPDT(false);
    }

    public void unfollow() throws Exception {
        String dir = System.getProperty("user.dir");
        String fn = dir + File.separator + "instarchiverPreferences.json";
        Object o = cb_users.getSelectionModel().getSelectedItem();

        if (o != null) {
            cb_users.getSelectionModel().clearSelection();
            cb_users.getItems().remove(o);
            List<String> lst = (List<String>)cb_users.getItems();

            if (!new File(fn).exists()) {
                createDefaultPreferences();
            }

            FileInputStream fis = new FileInputStream(fn);
            byte[] buff = new byte[fis.available()];
            fis.read(buff);
            fis.close();
            String content = new String(buff, "UTF-8");
            JSONObject prefs = new JSONObject(cryptText(content));
            JSONArray following = prefs.getJSONArray("following");
            following = new JSONArray();

            for (int i = 0; i < lst.size(); i++) {
                following.put(lst.get(i));
            }

            prefs.put("following", following);
            BufferedWriter bw = new BufferedWriter(new FileWriter(fn, false));
            bw.write(cryptText(prefs.toString()));
            bw.flush();
            bw.close();
        }
    }
}
