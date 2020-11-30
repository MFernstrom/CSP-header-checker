unit main;

{
  Version               0.8
  URL                   https://github.com/MFernstrom/SeurityHeaders
  Author                Marcus Fernstrom
  Source code license   Apache 2.0
  Images license        Paid license from https://www.flaticon.com/packs/monster-emojis-2, if used, you need to follow
                        the attribution license from the flaticon page or purchase your own.
}

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Dialogs, ComCtrls, StdCtrls, Buttons, ExtCtrls, ECLink,
  fphttpclient, opensslsockets, StrUtils;

type
  { THeaderKeyVal }
  THeaderKeyVal = Record
    description: String;
    key: String;
    value: String;
    needsValue: Boolean;
    present: Boolean;
  end;

  { THeader }
  THeader = class
    description: String;
    header: String;
    data: array of THeaderKeyVal;
    present: Boolean;
  end;

  { TForm1 }

  TForm1 = class(TForm)
    ECLink1: TECLink;
    GoButton: TBitBtn;
    Image1: TImage;
    HeaderDescription: TLabel;
    Image2: TImage;
    Image3: TImage;
    Label1: TLabel;
    Label2: TLabel;
    Raw: TMemo;
    Splitter1: TSplitter;
    url: TEdit;
    ImageList1: TImageList;
    HeadersList: TListView;
    ResultsList: TListView;
    procedure FormCreate(Sender: TObject);
    procedure GoButtonClick(Sender: TObject);
    procedure AnalyzeUri;
    procedure HeadersListClick(Sender: TObject);
    procedure AddHeaderKV(header: Integer; needsValue: Boolean; key, description: String);
    procedure ResetHeaders;
    procedure SetupHeaders;
    procedure UpdateHeadersListIcons;
    procedure ResetHeadersListIcons;
    function ExtractRest(str: String; chars: TSysCharSet ):String;
  private

  public

  end;

const
  version = '0.8.2';

var
  Form1: TForm1;
  Headers: Array of THeader;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin
  SetupHeaders;
  Caption := Caption + ' ' + version;
end;


// Starts the analysis
procedure TForm1.GoButtonClick(Sender: TObject);
begin
  GoButton.Caption := 'Plz wait';
  Application.ProcessMessages;
  AnalyzeUri;
  GoButton.Caption := 'Analyze';
end;


// Perform HTTP request and analyze the response headers
procedure TForm1.AnalyzeUri;
var
  client: tfphttpclient;
  res: String;
  i,v, k, o: Integer;
  header: THeader;
  headerName, headerVals, headerKVPair, headerKey, headerVal: String;
begin
  client := TFPHTTPClient.Create(nil);
  try
    client.AllowRedirect := true;
    try
      res := client.Get(url.Text);
    except
      Raw.Text := 'Request error' + Chr(10) + Chr(10);
      Raw.Append(format('%d - %s' + Chr(10), [client.ResponseStatusCode, client.ResponseStatusText]));
      Exit;
    end;
    Raw.Text := format('%d %s' + Chr(10), [client.ResponseStatusCode, client.ResponseStatusText]);
    Raw.Append('Method: GET' + Chr(10) + Chr(10));
    Raw.Append(client.ResponseHeaders.Text);
    //Raw.Append(format(Chr(10) + '%s', [res]));

    ResetHeaders;
    ResetHeadersListIcons;

    // TODO simplify loop
    for i:= 0 to client.ResponseHeaders.Count -1 do begin
      headerName := client.ResponseHeaders.Names[i];
      headerVals := client.ResponseHeaders.ValueFromIndex[i];

      for o := 0 to length(headers) -1 do begin
        header := headers[o];

        if headerName = header.header then begin
          // We have a matching header, now deal with the values
          for v := 1 to WordCount(headerVals, [';', ',']) do begin
            headerKVPair := ExtractWord(v, headerVals, [';', ',']);
            headerKVPair := Trim(headerKVPair);
            headerKey := ExtractWord(1, headerKVPair, ['=', ' ']);
            headerVal := ExtractRest(headerKVPair, ['=', ' ']);

            for k := 0 to length(header.data) -1 do begin
              if headerKey = headers[o].data[k].key then begin
                headers[o].data[k].value := headerVal;
                headers[o].data[k].present := true;
                headers[o].present := true;
              end;
            end;

          end;
        end;
      end;
    end;

    UpdateHeadersListIcons;
  finally
    client.Free;
  end;
end;


// When the user clicks on a header, show the data
procedure TForm1.HeadersListClick(Sender: TObject);
var
  item: TListItem;
  header: THeader;
  headerKV: THeaderKeyVal;
begin
  if HeadersList.SelCount = 0 then exit;

  item := HeadersList.Selected;

  ResultsList.Clear;

  for header in headers do begin
    if item.Caption = header.header then begin
      for headerKV in header.data do begin
        ResultsList.AddItem(headerKV.key, nil);
        ResultsList.Items[ResultsList.Items.Count-1].SubItems.Add(headerKV.value);
        ResultsList.Items[ResultsList.Items.Count-1].SubItems.Add(headerKV.description);
        if headerKV.present = true then ResultsList.Items[ResultsList.Items.Count-1].ImageIndex := 1
        else ResultsList.Items[ResultsList.Items.Count-1].ImageIndex := 0;
      end;
      HeaderDescription.Caption := header.description;
      break;
    end;
  end;
end;


// Adds a key, value, and description for a specific header
procedure TForm1.AddHeaderKV(header: Integer; needsValue: Boolean; key, description: String);
var
  arrLen: Integer;
begin
  SetLength(Headers[header].data, length(Headers[header].data) +1);
  arrLen := length(Headers[header].data) -1;
  Headers[header].data[arrLen].key := key;
  Headers[header].data[arrLen].description := description;
  Headers[header].data[arrLen].needsValue := needsValue;
  Headers[header].data[arrLen].present := false;
end;


// Adds/Resets all the header information
procedure TForm1.ResetHeaders;
var
  i, v: Integer;
begin
  for i := 0 to 9 do begin
    Headers[i].present := false;
    for v := 0 to length(Headers[i].data) -1 do begin
      Headers[i].data[v].present := false;
      Headers[i].data[v].value := '';
    end;
  end;
end;


// Adds the security headers
procedure TForm1.SetupHeaders;
var
  i: Integer;
begin
  SetLength(Headers, 10);

  for i := 0 to 9 do begin
    Headers[i] := THeader.Create;
  end;

  // Strict-Transport-Security / HSTS
  Headers[0].description := 'HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites against protocol downgrade attacks and cookie hijacking.' + Chr(10) + Chr(10) + 'It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol.' + Chr(10) + Chr(10) + 'HSTS is an IETF standards track protocol and is specified in RFC 6797.' + Chr(10) + Chr(10) + 'A server implements an HSTS policy by supplying a header (Strict-Transport-Security) over an HTTPS connection (HSTS headers over HTTP are ignored).';
  Headers[0].header := 'Strict-Transport-Security';
  SetLength(Headers[0].data, 0);
  AddHeaderKV(0, true, 'max-age', 'The time, in seconds, that the browser should remember that this site is only to be accessed using HTTPS.');
  AddHeaderKV(0, false, 'includeSubDomains', 'If this optional parameter is specified, this rule applies to all of the site’s subdomains as well.');


  // X-Frame-Options
  Headers[1].description := 'The X-Frame-Options response header improves the protection of web applications against clickjacking.' + Chr(10) + Chr(10) + 'It instructs the browser whether the content can be displayed within frames.' + Chr(10) + Chr(10) + 'The CSP frame-ancestors directive obsoletes the X-Frame-Options header.' + Chr(10) + Chr(10) + 'If a resource has both policies, the CSP frame-ancestors policy will be enforced and the X-Frame-Options policy will be ignored.';
  Headers[1].header := 'X-Frame-Options';
  SetLength(Headers[1].data, 0);
  AddHeaderKV(1, false, 'deny', 'No rendering within a frame');
  AddHeaderKV(1, false, 'sameorigin', 'No rendering if origin mismatch.');
  AddHeaderKV(1, true, 'allow-from', 'Allows rendering if framed by frame loaded from DOMAIN.');


  // X-Content-Type-Options
  Headers[2].description := 'Setting this header will prevent the browser from interpreting files as a different MIME type to what is specified in the Content-Type HTTP header (e.g. treating text/plain as text/css).';
  Headers[2].header := 'X-Content-Type-Options';
  SetLength(Headers[2].data, 0);
  AddHeaderKV(2, false, 'nosniff', 'Will prevent the browser from MIME-sniffing a response away from the declared content-type.');


  // Content-Security-Policy
  Headers[3].description := 'A Content Security Policy (CSP) requires careful tuning and precise definition of the policy.' + Chr(10) + Chr(10) + 'If enabled, CSP has significant impact on the way browsers render pages (e.g., inline JavaScript is disabled by default and must be explicitly allowed in the policy).' + Chr(10) + Chr(10) + 'CSP prevents a wide range of attacks, including cross-site scripting and other cross-site injections.';
  Headers[3].header := 'Content-Security-Policy';
  SetLength(Headers[3].data, 0);

  AddHeaderKV(3, true, 'base-uri', 'Define the base URI for relative URIs.');
  AddHeaderKV(3, true, 'default-src', 'Define loading policy for all resources type in case a resource type’s dedicated directive is not defined (fallback).');
  AddHeaderKV(3, true, 'script-src', 'Define which scripts the protected resource can execute.');
  AddHeaderKV(3, true, 'object-src', 'Define from where the protected resource can load plugins.');
  AddHeaderKV(3, true, 'style-src', 'Define which styles (CSS) can be applied to the protected resource.');
  AddHeaderKV(3, true, 'img-src', 'Define from where the protected resource can load images.');
  AddHeaderKV(3, true, 'media-src', 'Define from where the protected resource can load video and audio.');
  AddHeaderKV(3, true, 'frame-src', '(Deprecated and replaced by child-src) Define from where the protected resource can embed frames.');
  AddHeaderKV(3, true, 'child-src', 'Define from where the protected resource can embed frames.');
  AddHeaderKV(3, true, 'frame-ancestors', 'Define from where the protected resource can be embedded in frames.');
  AddHeaderKV(3, true, 'font-src', 'Define from where the protected resource can load fonts.');
  AddHeaderKV(3, true, 'connect-src', 'Define which URIs the protected resource can load using script interfaces.');
  AddHeaderKV(3, true, 'manifest-src', 'Define from where the protected resource can load manifests.');
  AddHeaderKV(3, true, 'form-action', 'Define which URIs can be used as the action of HTML form elements.');
  AddHeaderKV(3, true, 'sandbox', 'Specifies an HTML sandbox policy that the user agent applies to the protected resource.');
  AddHeaderKV(3, true, 'script-nonce', 'Define script execution by requiring the presence of the specified nonce on script elements.');
  AddHeaderKV(3, true, 'plugin-types', 'Define the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded.');
  AddHeaderKV(3, true, 'reflected-xss', 'Instruct the user agent to activate or deactivate any heuristics used to filter or block reflected cross-site scripting attacks, equivalent to the effects of the non-standard X-XSS-Protection header.');
  AddHeaderKV(3, true, 'block-all-mixed-content', 'Prevent the user agent from loading mixed content.');
  AddHeaderKV(3, true, 'upgrade-insecure-requests', 'Instruct the user agent to download insecure HTTP resources using HTTPS.');
  AddHeaderKV(3, true, 'referrer', '(Deprecated) Define information the user agent can send in the Referer header.');
  AddHeaderKV(3, true, 'report-uri', '(Deprecated and replaced by report-to) Specifies a URI to which the user agent sends reports about policy violation.');
  AddHeaderKV(3, true, 'report-to', 'Specifies a group (defined in the Report-To header) to which the user agent sends reports about policy violation.');


  // X-Permitted-Cross-Domain-Policies
  Headers[4].description := 'A cross-domain policy file is an XML document that grants a web client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily limited to these), permission to handle data across domains.' + Chr(10) + Chr(10) + 'When clients request content hosted on a particular source domain and that content makes requests directed towards a domain other than its own, the remote domain needs to host a cross-domain policy file that grants access to the source domain, allowing the client to continue the transaction.' + Chr(10) + Chr(10) + 'Normally a meta-policy is declared in the master policy file, but for those who can’t write to the root directory, they can also declare a meta-policy using the X-Permitted-Cross-Domain-Policies HTTP response header.';
  Headers[4].header := 'X-Permitted-Cross-Domain-Policies';
  SetLength(Headers[4].data, 0);

  AddHeaderKV(4, false, 'none', 'No policy files are allowed anywhere on the target server, including this master policy file.');
  AddHeaderKV(4, false, 'master-only', 'Only this master policy file is allowed.');
  AddHeaderKV(4, false, 'by-content-type', '[HTTP/HTTPS only] Only policy files served with Content-Type: text/x-cross-domain-policy are allowed.');
  AddHeaderKV(4, false, 'by-ftp-filename', '[FTP only] Only policy files whose file names are crossdomain.xml (i.e. URLs ending in /crossdomain.xml) are allowed.');
  AddHeaderKV(4, false, 'all', 'All policy files on this target domain are allowed.');


  // Referrer-Policy
  Headers[5].description := 'The Referrer-Policy HTTP header governs which referrer information, sent in the Referer header, should be included with requests made.';
  Headers[5].header := 'Referrer-Policy';
  SetLength(Headers[5].data, 0);

  AddHeaderKV(5, false, 'no-referrer', 'The Referer header will be omitted entirely. No referrer information is sent along with requests.');
  AddHeaderKV(5, false, 'no-referrer-when-downgrade', 'This is the user agent’s default behavior if no policy is specified. The origin is sent as referrer to a-priori as-much-secure destination (HTTPS -> HTTPS), but isn’t sent to a less secure destination (HTTPS -> HTTP).');
  AddHeaderKV(5, false, 'origin', 'Only send the origin of the document as the referrer in all cases. (e.g. the document https://example.com/page.html will send the referrer https://example.com/.)');
  AddHeaderKV(5, false, 'origin-when-cross-origin', 'Send a full URL when performing a same-origin request, but only send the origin of the document for other cases.');
  AddHeaderKV(5, false, 'same-origin', 'A referrer will be sent for same-site origins, but cross-origin requests will contain no referrer information.');
  AddHeaderKV(5, false, 'strict-origin', 'Only send the origin of the document as the referrer to a-priori as-much-secure destination (HTTPS -> HTTPS), but don’t send it to a less secure destination (HTTPS -> HTTP).');
  AddHeaderKV(5, false, 'strict-origin-when-cross-origin', 'Send a full URL when performing a same-origin request, only send the origin of the document to a-priori as-much-secure destination (HTTPS -> HTTPS), and send no header to a less secure destination (HTTPS -> HTTP).');
  AddHeaderKV(5, false, 'unsafe-url', 'Send a full URL (stripped from parameters) when performing a a same-origin or cross-origin request.');


  // Feature-Policy
  Headers[6].description := 'The Feature-Policy header is an experimental feature that allows developers to selectively enable and disable use of various browser features and APIs.' + Chr(10) + Chr(10) + 'The two most well supported values are microphone and camera.';
  Headers[6].header := 'Feature-Policy';
  SetLength(Headers[6].data, 0);

  AddHeaderKV(6, false, 'accelerometer', 'Controls access to accelerometer sensors on the device.');
  AddHeaderKV(6, false, 'ambient-light-sensor', 'Controls access to ambient light sensors on the device.');
  AddHeaderKV(6, false, 'autoplay', 'Controls access to autoplay through play() and the autoplay attribute.');
  AddHeaderKV(6, false, 'battery', 'Controls access to the BatteryManager API.');
  AddHeaderKV(6, false, 'camera', 'Controls access to video input devices.');
  AddHeaderKV(6, false, 'display-capture', 'Controls access to capturing the display output.');
  AddHeaderKV(6, false, 'document-domain', 'Controls access to setting document.domain.');
  AddHeaderKV(6, false, 'encrypted-media', 'Controls whether requestMediaKeySystemAccess() is allowed.');
  AddHeaderKV(6, false, 'fullscreen', 'Controls whether requestFullscreen() is allowed.');
  AddHeaderKV(6, false, 'geolocation', 'Controls access to the Geolocation interface.');
  AddHeaderKV(6, false, 'gyroscope', 'Controls access to gyroscope sensors on the device.');
  AddHeaderKV(6, false, 'magnetometer', 'Controls access to magnetometer sensors on the device.');
  AddHeaderKV(6, false, 'microphone', 'Controls access to audio input devices.');
  AddHeaderKV(6, false, 'midi', 'Controls access to requestMIDIAccess() method.');
  AddHeaderKV(6, false, 'navigation-override', 'Controls access to override of the spatial navigation API.');
  AddHeaderKV(6, false, 'payment', 'Controls access to the PaymentRequest interface.');
  AddHeaderKV(6, false, 'picture-in-picture', 'Controls access to picture-in-picture.');
  AddHeaderKV(6, false, 'speaker', 'Controls access to audio output devices.');
  AddHeaderKV(6, false, 'usb', 'Controls access to USB devices.');
  AddHeaderKV(6, false, 'vibrate', '(deprecated) Controls access to the vibrate() method.');
  AddHeaderKV(6, false, 'vr', '(deprecated) Controls access to VR displays.');


  // Expect-CT
  Headers[7].description := 'The Expect-CT header is used by a server to indicate that browsers should evaluate connections to the host for Certificate Transparency compliance.' + Chr(10) + Chr(10) + 'In Chrome 61 (Aug 2017) Chrome enabled its enforcement via SCT by default (source).' + Chr(10) + Chr(10) + 'You can still use this header to specify an report-uri.' + Chr(10) + Chr(10) + 'This header comes from the (now expired) internet draft Expect-CT Extension for HTTP.';
  Headers[7].header := 'Expect-CT';
  SetLength(Headers[7].data, 0);

  AddHeaderKV(7, true, 'report-uri', '(Optional) Indicates the URL to which the browser should report Expect-CT failures.');
  AddHeaderKV(7, false, 'enforce', '(Optional) A valueless directive that, if present, signals to the browser that compliance to the CT Policy should be enforced (rather than report-only) and that the browser should refuse future connections that violate its CT Policy. When both the enforce and report-uri directives are present, the configuration is referred to as an “enforce-and-report” configuration, signalling to the browser both that compliance to the CT Policy should be enforced and that violations should be reported.');
  AddHeaderKV(7, true, 'max-age', 'Specifies the number of seconds after the response is received the browser should remember and enforce certificate transparency compliance.');


  // X-XSS-Protection
  Headers[8].description := 'This header enables the cross-site scripting (XSS) filter in your browser.' + Chr(10) + Chr(10) + 'Warning: The X-XSS-Protection header has been deprecated by modern browsers and its use can introduce additional security issues on the client side.' + Chr(10) + Chr(10) + 'As such, it is recommended to set the header as X-XSS-Protection: 0 in order to disable the XSS Auditor, and not allow it to take the default behavior of the browser handling the response.' + Chr(10) + Chr(10) + 'Please use Content-Security-Policy instead.';
  Headers[8].header := 'X-XSS-Protection';
  SetLength(Headers[8].data, 0);

  AddHeaderKV(8, false, '0', 'Filter disabled.');
  AddHeaderKV(8, false, '1', 'Filter enabled. If a cross-site scripting attack is detected, in order to stop the attack, the browser will sanitize the page.');
  AddHeaderKV(8, false, 'mode', 'Filter enabled. Rather than sanitize the page, when a XSS attack is detected, the browser will prevent rendering of the page.');
  AddHeaderKV(8, true, 'report', 'Filter enabled. The browser will sanitize the page and report the violation. This is a Chromium function utilizing CSP violation reports to send details to a URI of your choice.');
end;


// Loops the current results and sets icons accordingly
procedure TForm1.UpdateHeadersListIcons;
var
  i: Integer;
  header: THeader;
begin
  for i := 0 to HeadersList.Items.Count -1 do begin
    for header in Headers do begin
      if (HeadersList.Items[i].Caption = header.header) and (header.present = true) then begin
        HeadersList.Items[i].ImageIndex := 1;
        break;
      end else
        HeadersList.Items[i].ImageIndex := 0;
    end;
  end;
end;


// Resets the icons in the headers list to the default grey
procedure TForm1.ResetHeadersListIcons;
var
  i: Integer;
begin
  for i := 0 to HeadersList.Items.Count -1 do begin
    HeadersList.Items[i].ImageIndex := 0;
  end;
end;


// Returns the string minus the first word
function TForm1.ExtractRest(str: String; chars: TSysCharSet): String;
var
  firstWordLen: Integer;
  tmp: String;
begin
  tmp := ExtractWord(1, str, chars);
  firstWordLen := length(tmp) + 1;
  Result := RightStr(str, length(str) - firstWordLen);
end;

end.
