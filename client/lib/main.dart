import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:http/http.dart';
import 'package:http/io_client.dart';
import 'package:pointycastle/api.dart' as api;
import 'package:pointycastle/asymmetric/api.dart';
import "crypto.dart";
import 'package:path_provider/path_provider.dart';

void main() => runApp(MyApp());
HttpClient client = new HttpClient()
  ..badCertificateCallback =
      ((X509Certificate cert, String host, int port) => true);
IOClient ioClient = new IOClient(client);

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Node server demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: Scaffold(
        appBar: AppBar(title: Text('Hyperledger Fabric Flutter Client')),
        body: BodyWidget(),
      ),
    );
  }
}

class BodyWidget extends StatefulWidget {
  @override
  BodyWidgetState createState() {
    return new BodyWidgetState();
  }
}

class BodyWidgetState extends State<BodyWidget> {
  String clipboard = '';
  api.AsymmetricKeyPair<api.PublicKey, api.PrivateKey> keypair;
  RSAPrivateKey privateKey;
  bool ready = false;
  Uint8List unsignedProposal;
  String sig;
  String csr;
  String certPem;
  Object proposalResponse;

  // Create a text controller and use it to retrieve the current value
  // of the TextField.
  final channelController = TextEditingController();
  final certificateController = TextEditingController();
  final addressController = TextEditingController();
  final nameController = TextEditingController();

  @override
  void dispose() {
    // Clean up the controller when the widget is disposed.
    channelController.dispose();
    certificateController.dispose();
    addressController.dispose();
    nameController.dispose();

    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(10.0),
      child: Align(
        alignment: Alignment.topCenter,
        child: SizedBox(
          width: 500,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: <Widget>[
              ButtonTheme(
                minWidth: 400.0,
                height: 40.0,
                textTheme: ButtonTextTheme.primary,
                child: RaisedButton(
                  child: Text('Generate Key Pair'),
                  onPressed: () async {
                    showDialog(
                        context: context,
                        builder: (BuildContext context) {
                          return Center(
                            child: CircularProgressIndicator(),
                          );
                        });
                    await _makeKeypairRequest();
                    Navigator.pop(context);
                  },
                ),
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Get Private Key'),
                    onPressed: () {
                      _makePrivateKeyRequest();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Get Public Key'),
                    onPressed: () {
                      _makePublicKeyRequest();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: TextField(
                  controller: channelController,
                  decoration: InputDecoration(
                    border: OutlineInputBorder(),
                    labelText: 'Channel ID',
                    contentPadding: const EdgeInsets.symmetric(
                        vertical: 8.0, horizontal: 8.0),
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Setup Fabric Channel'),
                    onPressed: () {
                      _makeSetupChannelRequest(channelController.text);
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: TextField(
                  controller: certificateController,
                  decoration: InputDecoration(
                    labelText: 'Certificate Path',
                    contentPadding: const EdgeInsets.symmetric(
                        vertical: 4.0, horizontal: 4.0),
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: TextField(
                  controller: addressController,
                  decoration: InputDecoration(
                    labelText: 'Listen Address',
                    contentPadding: const EdgeInsets.symmetric(
                        vertical: 4.0, horizontal: 4.0),
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: TextField(
                  controller: nameController,
                  decoration: InputDecoration(
                    labelText: 'Name',
                    contentPadding: const EdgeInsets.symmetric(
                        vertical: 4.0, horizontal: 4.0),
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Setup Fabric Peer / Orderer'),
                    onPressed: () {
                      _showAlert();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Generate Certificate Signing Request'),
                    onPressed: () {
                      _makeCSRGeneration();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Request Certificate from Fabric CA'),
                    onPressed: () {
                      _makeCertificateGenerationRequest();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Request Unsigned Proposal Generation'),
                    onPressed: () {
                      _makeUnsignedProposalGenerationRequest();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Sign Proposal'),
                    onPressed: () {
                      _makeSigningProposal();
                    },
                  ),
                ),
                visible: ready,
              ),
              Visibility(
                child: ButtonTheme(
                  minWidth: 400.0,
                  height: 40.0,
                  textTheme: ButtonTextTheme.primary,
                  child: RaisedButton(
                    child: Text('Send Signed Proposal'),
                    onPressed: () {
                      _makeProposalSendingRequest();
                    },
                  ),
                ),
                visible: ready,
              ),
              Expanded(
                child: SelectableText(clipboard),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _showAlert() async {
    return showDialog<void>(
      context: context,
      barrierDismissible: false, // user must tap button!
      builder: (BuildContext context) {
        return new AlertDialog(
          title: Text('Confirmation'),
          content: SingleChildScrollView(
            child: ListBody(
              children: <Widget>[
                Text('Choose peer or orderer for this setup?'),
              ],
            ),
          ),
          actions: <Widget>[
            FlatButton(
              child: Text('Peer'),
              onPressed: () {
                _makeSetupPeerRequest(certificateController.text,
                    addressController.text, nameController.text);
              },
            ),
            FlatButton(
              child: Text('Orderer'),
              onPressed: () {
                _makeSetupOrdererRequest(certificateController.text,
                    addressController.text, nameController.text);
              },
            ),
          ],
        );
      },
    );
  }

  _writeToFile(String encodedString, String filename) async {
    Directory tempDir = await getTemporaryDirectory();
    String tempPath = tempDir.path;
    final file = new File('$tempPath/$filename');
    await file.writeAsString(encodedString);
    return file;
  }

  _upload(File file, String url) async {
    if (file == null) return null;
    String filebody = file.readAsStringSync();
    String filename = file.path.split("/").last;
    Response res =
        await ioClient.post(url, body: {"content": filebody, "name": filename});
    return res;
  }

  _makeKeypairRequest() async {
    var pair = await makeGenerationRequest();
    setState(() {
      keypair = pair;
      ready = true;
    });
  }

  _makeCSRGeneration() async {
    setState(() {
      csr = generateCSR(keypair.privateKey, keypair.publicKey);
      clipboard = csr;
    });
  }

  _makeSetupChannelRequest(String channelId) async {
    Response response = await ioClient.get(_requestChannelSetup(channelId));
    setState(() {
      clipboard = response.body;
    });
  }

  _makeSetupPeerRequest(String cert, String address, String name) async {
    Response response =
        await ioClient.get(_requestPeerSetup(cert, address, name));
    setState(() {
      clipboard = response.body;
    });
    Navigator.of(context).pop();
  }

  _makeSetupOrdererRequest(String cert, String address, String name) async {
    Response response =
        await ioClient.get(_requestOrdererSetup(cert, address, name));
    setState(() {
      clipboard = response.body;
    });
    Navigator.of(context).pop();
  }

  _makePrivateKeyRequest() async {
    var privateKeyPem = encodePrivateKeyToPem(keypair.privateKey);
    setState(() {
      clipboard = privateKeyPem;
      privateKey = keypair.privateKey;
    });
  }

  _makePublicKeyRequest() async {
    var publicKeyPem = encodePublicKeyToPem(keypair.publicKey);
    setState(() {
      clipboard = publicKeyPem;
    });
  }

  _makeUnsignedProposalGenerationRequest() async {
    Response response = await ioClient
        .post(_requestUnsignedProposalGeneration(), body: {"cert": certPem});
    setState(() {
      unsignedProposal = response.bodyBytes;
      clipboard = response.body;
    });
  }

  _makeSigningProposal() async {
    String signature = sign(unsignedProposal, privateKey);
    setState(() {
      sig = signature;
      clipboard = sig;
    });
  }

  _makeProposalSendingRequest() async {
    File file = await _writeToFile(sig, 'signature.txt');
    Response response = await _upload(file, _requestProposalSending());
    setState(() {
      proposalResponse = response.body;
      clipboard = proposalResponse;
    });
  }

  _makeCertificateGenerationRequest() async {
    File file = await _writeToFile(csr, 'cert.csr');
    Response response = await _upload(file, _requestCertificate());
    setState(() {
      certPem = response.body;
      clipboard = certPem;
    });
  }

  String _requestChannelSetup(String channelId) {
    if (Platform.isAndroid)
      return 'https://10.0.2.2:8081/setupChannel?id=' + channelId;
    else // for iOS simulator
      return 'https://localhost:8081/setupChannel?id=' + channelId;
  }

  String _requestPeerSetup(String cert, String address, String name) {
    if (Platform.isAndroid)
      return 'https://10.0.2.2:8081/setupPeer?cert=' +
          cert +
          "&address=" +
          address +
          "&name=" +
          name;
    else // for iOS simulator
      return 'https://localhost:8081/setupPeer?cert=' +
          cert +
          "&address=" +
          address +
          "&name=" +
          name;
  }

  String _requestOrdererSetup(String cert, String address, String name) {
    if (Platform.isAndroid)
      return 'https://10.0.2.2:8081/setupOrderer?cert=' +
          cert +
          "&address=" +
          address +
          "&name=" +
          name;
    else // for iOS simulator
      return 'https://localhost:8081/setupOrderer?cert=' +
          cert +
          "&address=" +
          address +
          "&name=" +
          name;
  }

  String _requestProposalSending() {
    if (Platform.isAndroid)
      return 'https://10.0.2.2:8081/sendSignedProposal';
    else // for iOS simulator
      return 'https://localhost:8081/sendSignedProposal';
  }

  String _requestUnsignedProposalGeneration() {
    if (Platform.isAndroid)
      return 'https://10.0.2.2:8081/generateUnsignedProposal';
    else // for iOS simulator
      return 'https://localhost:8081/generateUnsignedProposal';
  }

  String _requestCertificate() {
    if (Platform.isAndroid)
      return 'https://10.0.2.2:8081/requestCertificate';
    else // for iOS simulator
      return 'https://localhost:8081/requestCertificate';
  }
}
