// #include "pp/PacketProcessor.h"
// #include "pp/PacketProcessorTcpMonitor.h"

// static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie)
// {
//     // extract the connection manager from the user cookie
//     TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

//     // check if this flow already appears in the connection manager. If not add it
//     TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
//     if (iter == connMgr->end())
//     {
//         connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
//         iter = connMgr->find(tcpData.getConnectionData().flowKey);
//     }

//     int8_t side;

//     // if the user wants to write each side in a different file - set side as the sideIndex, otherwise write everything to the same file ("side 0")
//     if (GlobalConfig::getInstance().separateSides)
//       side = sideIndex;
//     else
//       side = 0;

//     // if the file stream on the relevant side isn't open yet (meaning it's the first data on this connection)
//     if (iter->second.fileStreams[side] == NULL)
//     {
//       // add the flow key of this connection to the list of open connections. If the return value isn't NULL it means that there are too many open files
//       // and we need to close the connection with least recently used file(s) in order to open a new one.
//       // The connection with the least recently used file is the return value
//       uint32_t flowKeyToCloseFiles;
//       int result = GlobalConfig::getInstance().getRecentConnsWithActivity()->put(tcpData.getConnectionData().flowKey, &flowKeyToCloseFiles);

//       // if result equals to 1 it means we need to close the open files in this connection (the one with the least recently used files)
//       if (result == 1)
//       {
//         // find the connection from the flow key
//         TcpReassemblyConnMgrIter iter2 = connMgr->find(flowKeyToCloseFiles);
//         if (iter2 != connMgr->end())
//         {
//           // close files on both sides (if they're open)
//           for (int index = 0; index < 2; index++)
//           {
//             if (iter2->second.fileStreams[index] != NULL)
//             {
//               // close the file
//               GlobalConfig::getInstance().closeFileSteam(iter2->second.fileStreams[index]);
//               iter2->second.fileStreams[index] = NULL;

//               // set the reopen flag to true to indicate that next time this file will be opened it will be opened in append mode (and not overwrite mode)
//               iter2->second.reopenFileStreams[index] = true;
//             }
//           }
//         }
//       }

//       // get the file name according to the 5-tuple etc.
//       std::string fileName = GlobalConfig::getInstance().getFileName(tcpData.getConnectionData(), sideIndex, GlobalConfig::getInstance().separateSides) + ".txt";

//       // open the file in overwrite mode (if this is the first time the file is opened) or in append mode (if it was already opened before)
//       iter->second.fileStreams[side] = GlobalConfig::getInstance().openFileStream(fileName, iter->second.reopenFileStreams[side]);
// 	}

// 	// if this messages comes on a different side than previous message seen on this connection
// 	if (sideIndex != iter->second.curSide)
// 	{
// 		// count number of message in each side
// 		iter->second.numOfMessagesFromSide[sideIndex]++;

// 		// set side index as the current active side
// 		iter->second.curSide = sideIndex;
// 	}

// 	// count number of packets and bytes in each side of the connection
// 	iter->second.numOfDataPackets[sideIndex]++;
// 	iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

// 	// write the new data to the file
// 	iter->second.fileStreams[side]->write((char*)tcpData.getData(), tcpData.getDataLength());
// }


// /**
//  * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
//  */
// static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
// {
// 	// get a pointer to the connection manager
// 	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

// 	// look for the connection in the connection manager
// 	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

// 	// assuming it's a new connection
// 	if (iter == connMgr->end())
// 	{
// 		// add it to the connection manager
// 		connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
// 	}
// }


// /**
//  * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
//  * by the user
//  */
// static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
// {
// 	// get a pointer to the connection manager
// 	TcpReassemblyConnMgr* connMgr = (TcpReassemblyConnMgr*)userCookie;

// 	// find the connection in the connection manager by the flow key
// 	TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

// 	// connection wasn't found - shouldn't get here
// 	if (iter == connMgr->end())
// 		return;

// 	// write a metadata file if required by the user
// 	if (GlobalConfig::getInstance().writeMetadata)
// 	{
// 		std::string fileName = GlobalConfig::getInstance().getFileName(connectionData, 0, false) + "-metadata.txt";
// 		std::ofstream metadataFile(fileName.c_str());
// 		metadataFile << "Number of data packets in side 0:  " << iter->second.numOfDataPackets[0] << std::endl;
// 		metadataFile << "Number of data packets in side 1:  " << iter->second.numOfDataPackets[1] << std::endl;
// 		metadataFile << "Total number of data packets:      " << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << std::endl;
// 		metadataFile << std::endl;
// 		metadataFile << "Number of bytes in side 0:         " << iter->second.bytesFromSide[0] << std::endl;
// 		metadataFile << "Number of bytes in side 1:         " << iter->second.bytesFromSide[1] << std::endl;
// 		metadataFile << "Total number of bytes:             " << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << std::endl;
// 		metadataFile << std::endl;
// 		metadataFile << "Number of messages in side 0:      " << iter->second.numOfMessagesFromSide[0] << std::endl;
// 		metadataFile << "Number of messages in side 1:      " << iter->second.numOfMessagesFromSide[1] << std::endl;
// 		metadataFile.close();
// 	}

// 	// remove the connection from the connection manager
// 	connMgr->erase(iter);
// }