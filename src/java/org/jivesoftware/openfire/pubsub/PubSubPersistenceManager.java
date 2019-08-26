/**
 * $RCSfile: $
 * $Revision: $
 * $Date: $
 *
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.pubsub;

import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.database.DbConnectionManager.DatabaseType;
import org.jivesoftware.openfire.cluster.ClusterManager;
import org.jivesoftware.openfire.pubsub.cluster.FlushTask;
import org.jivesoftware.openfire.pubsub.models.AccessModel;
import org.jivesoftware.openfire.pubsub.models.PublisherModel;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.jivesoftware.util.TaskEngine;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;

/**
 * A manager responsible for ensuring node persistence.
 *
 * @author Matt Tucker
 */
public class PubSubPersistenceManager implements PubSubPersistenceProvider {

    private static final Logger log = LoggerFactory.getLogger(PubSubPersistenceManager.class);

    private static final String PERSISTENT_NODES = "SELECT serviceID, nodeID, maxItems " +
    		"FROM ofPubsubNode WHERE leaf=1 AND persistItems=1 AND maxItems > 0";
    
    private static final String PURGE_FOR_SIZE =
    		"DELETE FROM ofPubsubItem LEFT JOIN " +
			"(SELECT id FROM ofPubsubItem WHERE serviceID=? AND nodeID=? " +
			"ORDER BY creationDate DESC LIMIT ?) AS noDelete " +
			"ON ofPubsubItem.id = noDelete.id WHERE noDelete.id IS NULL AND " +
			"ofPubsubItem.serviceID = ? AND nodeID = ?";
    
    private static final String PURGE_FOR_SIZE_MYSQL =
		"DELETE ofPubsubItem FROM ofPubsubItem LEFT JOIN " +
			"(SELECT id FROM ofPubsubItem WHERE serviceID=? AND nodeID=? " +
			"ORDER BY creationDate DESC LIMIT ?) AS noDelete " +
			"ON ofPubsubItem.id = noDelete.id WHERE noDelete.id IS NULL AND " +
			"ofPubsubItem.serviceID = ? AND nodeID = ?";

    private static final String PURGE_FOR_SIZE_POSTGRESQL = 
    		"DELETE from ofPubsubItem where id in " +
    		"(select ofPubsubItem.id FROM ofPubsubItem LEFT JOIN " +
    		"(SELECT id FROM ofPubsubItem WHERE serviceID=? AND nodeID=? " +
    		"ORDER BY creationDate DESC LIMIT ?) AS noDelete " +
    		"ON ofPubsubItem.id = noDelete.id WHERE noDelete.id IS NULL " +
    		"AND ofPubsubItem.serviceID = ? AND nodeID = ?)";

	private static final String PURGE_FOR_SIZE_HSQLDB = "DELETE FROM ofPubsubItem WHERE serviceID=? AND nodeID=? AND id NOT IN "
			+ "(SELECT id FROM ofPubsubItem WHERE serviceID=? AND nodeID=? ORDER BY creationDate DESC LIMIT ?)";

	private static final String LOAD_NODES =
            "SELECT nodeID, leaf, creationDate, modificationDate, parent, deliverPayloads, " +
            "maxPayloadSize, persistItems, maxItems, notifyConfigChanges, notifyDelete, " +
            "notifyRetract, presenceBased, sendItemSubscribe, publisherModel, " +
            "subscriptionEnabled, configSubscription, accessModel, payloadType, " +
            "bodyXSLT, dataformXSLT, creator, description, language, name, " +
            "replyPolicy, associationPolicy, maxLeafNodes FROM ofPubsubNode " +
 "WHERE serviceID=?";

	private static final String LOAD_NODE = LOAD_NODES + " AND nodeID=?";

    private static final String UPDATE_NODE =
            "UPDATE ofPubsubNode SET modificationDate=?, parent=?, deliverPayloads=?, " +
            "maxPayloadSize=?, persistItems=?, maxItems=?, " +
            "notifyConfigChanges=?, notifyDelete=?, notifyRetract=?, presenceBased=?, " +
            "sendItemSubscribe=?, publisherModel=?, subscriptionEnabled=?, configSubscription=?, " +
            "accessModel=?, payloadType=?, bodyXSLT=?, dataformXSLT=?, description=?, " +
            "language=?, name=?, replyPolicy=?, associationPolicy=?, maxLeafNodes=? " +
            "WHERE serviceID=? AND nodeID=?";
    private static final String ADD_NODE =
            "INSERT INTO ofPubsubNode (serviceID, nodeID, leaf, creationDate, modificationDate, " +
            "parent, deliverPayloads, maxPayloadSize, persistItems, maxItems, " +
            "notifyConfigChanges, notifyDelete, notifyRetract, presenceBased, " +
            "sendItemSubscribe, publisherModel, subscriptionEnabled, configSubscription, " +
            "accessModel, payloadType, bodyXSLT, dataformXSLT, creator, description, " +
            "language, name, replyPolicy, associationPolicy, maxLeafNodes) " +
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    private static final String DELETE_NODE =
            "DELETE FROM ofPubsubNode WHERE serviceID=? AND nodeID=?";

    private static final String LOAD_NODES_JIDS =
            "SELECT nodeID, jid, associationType FROM ofPubsubNodeJIDs WHERE serviceID=?";
	private static final String LOAD_NODE_JIDS = "SELECT nodeID, jid, associationType FROM ofPubsubNodeJIDs WHERE serviceID=? AND nodeID=?";
	private static final String ADD_NODE_JIDS =
            "INSERT INTO ofPubsubNodeJIDs (serviceID, nodeID, jid, associationType) " +
            "VALUES (?,?,?,?)";
    private static final String DELETE_NODE_JIDS =
            "DELETE FROM ofPubsubNodeJIDs WHERE serviceID=? AND nodeID=?";

    private static final String LOAD_NODES_GROUPS =
            "SELECT nodeID, rosterGroup FROM ofPubsubNodeGroups WHERE serviceID=?";
	private static final String LOAD_NODE_GROUPS = "SELECT nodeID, rosterGroup FROM ofPubsubNodeGroups WHERE serviceID=? AND nodeID=?";
    private static final String ADD_NODE_GROUPS =
            "INSERT INTO ofPubsubNodeGroups (serviceID, nodeID, rosterGroup) " +
            "VALUES (?,?,?)";
    private static final String DELETE_NODE_GROUPS =
            "DELETE FROM ofPubsubNodeGroups WHERE serviceID=? AND nodeID=?";

    private static final String LOAD_AFFILIATIONS =
            "SELECT nodeID,jid,affiliation FROM ofPubsubAffiliation WHERE serviceID=? " +
            "ORDER BY nodeID";
	private static final String LOAD_NODE_AFFILIATIONS = "SELECT nodeID,jid,affiliation FROM ofPubsubAffiliation WHERE serviceID=? AND nodeID=?";
    private static final String ADD_AFFILIATION =
            "INSERT INTO ofPubsubAffiliation (serviceID,nodeID,jid,affiliation) VALUES (?,?,?,?)";
    private static final String UPDATE_AFFILIATION =
            "UPDATE ofPubsubAffiliation SET affiliation=? WHERE serviceID=? AND nodeID=? AND jid=?";
    private static final String DELETE_AFFILIATION =
            "DELETE FROM ofPubsubAffiliation WHERE serviceID=? AND nodeID=? AND jid=?";
    private static final String DELETE_AFFILIATIONS =
            "DELETE FROM ofPubsubAffiliation WHERE serviceID=? AND nodeID=?";

	private static final String LOAD_SUBSCRIPTIONS_BASE = "SELECT nodeID, id, jid, owner, state, deliver, digest, digest_frequency, "
			+ "expire, includeBody, showValues, subscriptionType, subscriptionDepth, "
			+ "keyword FROM ofPubsubSubscription WHERE serviceID=? ";
	private static final String LOAD_NODE_SUBSCRIPTION = LOAD_SUBSCRIPTIONS_BASE + "AND nodeID=? AND id=?";
	private static final String LOAD_NODE_SUBSCRIPTIONS = LOAD_SUBSCRIPTIONS_BASE + "AND nodeID=?";
	private static final String LOAD_SUBSCRIPTIONS = LOAD_SUBSCRIPTIONS_BASE + "ORDER BY nodeID";

    private static final String ADD_SUBSCRIPTION =
            "INSERT INTO ofPubsubSubscription (serviceID, nodeID, id, jid, owner, state, " +
            "deliver, digest, digest_frequency, expire, includeBody, showValues, " +
            "subscriptionType, subscriptionDepth, keyword) " +
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    private static final String UPDATE_SUBSCRIPTION =
            "UPDATE ofPubsubSubscription SET owner=?, state=?, deliver=?, digest=?, " +
            "digest_frequency=?, expire=?, includeBody=?, showValues=?, subscriptionType=?, " +
            "subscriptionDepth=?, keyword=? WHERE serviceID=? AND nodeID=? AND id=?";
    private static final String DELETE_SUBSCRIPTION =
            "DELETE FROM ofPubsubSubscription WHERE serviceID=? AND nodeID=? AND id=?";
    private static final String DELETE_SUBSCRIPTIONS =
            "DELETE FROM ofPubsubSubscription WHERE serviceID=? AND nodeID=?";
    private static final String LOAD_ITEMS =
            "SELECT id,jid,creationDate,payload FROM ofPubsubItem " +
            "WHERE serviceID=? AND nodeID=? ORDER BY creationDate DESC";
    private static final String LOAD_ITEM =
            "SELECT jid,creationDate,payload FROM ofPubsubItem " +
            "WHERE serviceID=? AND nodeID=? AND id=?";
    private static final String LOAD_LAST_ITEM =
            "SELECT id,jid,creationDate,payload FROM ofPubsubItem " +
            "WHERE serviceID=? AND nodeID=? ORDER BY creationDate DESC";
    private static final String ADD_ITEM =
            "INSERT INTO ofPubsubItem (serviceID,nodeID,id,jid,creationDate,payload) " +
            "VALUES (?,?,?,?,?,?)";
    private static final String DELETE_ITEM =
            "DELETE FROM ofPubsubItem WHERE serviceID=? AND nodeID=? AND id=?";
    private static final String DELETE_ITEMS =
            "DELETE FROM ofPubsubItem WHERE serviceID=? AND nodeID=?";

    private static final String LOAD_DEFAULT_CONF =
            "SELECT deliverPayloads, maxPayloadSize, persistItems, maxItems, " +
            "notifyConfigChanges, notifyDelete, notifyRetract, presenceBased, " +
            "sendItemSubscribe, publisherModel, subscriptionEnabled, accessModel, language, " +
            "replyPolicy, associationPolicy, maxLeafNodes " +
            "FROM ofPubsubDefaultConf WHERE serviceID=? AND leaf=?";
    private static final String UPDATE_DEFAULT_CONF =
            "UPDATE ofPubsubDefaultConf SET deliverPayloads=?, maxPayloadSize=?, persistItems=?, " +
            "maxItems=?, notifyConfigChanges=?, notifyDelete=?, notifyRetract=?, " +
            "presenceBased=?, sendItemSubscribe=?, publisherModel=?, subscriptionEnabled=?, " +
            "accessModel=?, language=?, replyPolicy=?, associationPolicy=?, maxLeafNodes=? " +
            "WHERE serviceID=? AND leaf=?";
    private static final String ADD_DEFAULT_CONF =
            "INSERT INTO ofPubsubDefaultConf (serviceID, leaf, deliverPayloads, maxPayloadSize, " +
            "persistItems, maxItems, notifyConfigChanges, notifyDelete, notifyRetract, " +
            "presenceBased, sendItemSubscribe, publisherModel, subscriptionEnabled, " +
            "accessModel, language, replyPolicy, associationPolicy, maxLeafNodes) " +
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    /**
     * Pseudo-random number generator is used to offset timing for scheduled tasks
     * within a cluster (so they don't run at the same time on all members).
     */
    private Random prng = new Random();
    
    /**
     * Flush timer delay is configurable, but not less than 20 seconds (default: 2 mins)
     */
    private static long flushTimerDelay = Math.max(20000,
    		JiveGlobals.getIntProperty("xmpp.pubsub.flush.timer", 120)*1000);

    /**
     * Purge timer delay is configurable, but not less than 60 seconds (default: 5 mins)
     */
    private static long purgeTimerDelay = Math.max(60000, 
    		JiveGlobals.getIntProperty("xmpp.pubsub.purge.timer", 300)*1000);

    /**
     * Maximum number of published items allowed in the write cache
     * before being flushed to the database.
     */
	private static final int MAX_ITEMS_FLUSH = JiveGlobals.getIntProperty("xmpp.pubsub.flush.max", 1000);

    /**
     * Maximum number of rows that will be fetched from the published items table.
     */
    private static final int MAX_ROWS_FETCH = JiveGlobals.getIntProperty("xmpp.pubsub.fetch.max", 2000);

    /**
     * Number of retry attempts we will make trying to write an item to the DB
     */
	private static final int MAX_ITEM_RETRY = JiveGlobals.getIntProperty("xmpp.pubsub.item.retry", 1);
    
    /**
     * Queue that holds the (wrapped) items that need to be added to the database.
     */
    private Deque<RetryWrapper> itemsToAdd = new ConcurrentLinkedDeque<>();

    /**
     * Queue that holds the items that need to be deleted from the database.
     */
    private Deque<PublishedItem> itemsToDelete = new ConcurrentLinkedDeque<>();

    /**
     * Keeps reference to published items that haven't been persisted yet so they
     * can be removed before being deleted. Note these items are wrapped via the
     * RetryWrapper to allow multiple persistence attempts when needed.
     */
    private final HashMap<String, RetryWrapper> itemsPending = new HashMap<>();

    private ConcurrentMap<Node.UniqueIdentifier, List<NodeOperation>> nodesToProcess = new ConcurrentHashMap<>();

    static class NodeOperation {

        enum Action {
            CREATE,
            UPDATE,
            REMOVE,
            CREATE_AFFILIATION,
            UPDATE_AFFILIATION,
            REMOVE_AFFILIATION,
            CREATE_SUBSCRIPTION,
            UPDATE_SUBSCRIPTION,
            REMOVE_SUBSCRIPTION
        }

        final Node node;
        final Action action;
        final NodeAffiliate affiliate;
        final NodeSubscription subscription;

        private NodeOperation( final Node node, final Action action, final NodeAffiliate affiliate, final NodeSubscription subscription ) {
            if ( node == null ) {
                throw new IllegalArgumentException( "Argument 'node' cannot be null." );
            }
            if ( action == null ) {
                throw new IllegalArgumentException( "Argument 'action' cannot be null." );
            }
            if ( affiliate == null && Arrays.asList( Action.CREATE_AFFILIATION, Action.UPDATE_AFFILIATION, Action.REMOVE_AFFILIATION ).contains( action ) ) {
                throw new IllegalArgumentException( "Argument 'affiliate' cannot be null when 'action' is " + action );
            }
            if ( subscription == null && Arrays.asList( Action.CREATE_SUBSCRIPTION, Action.UPDATE_SUBSCRIPTION, Action.REMOVE_SUBSCRIPTION ).contains( action ) ) {
                throw new IllegalArgumentException( "Argument 'subscription' cannot be null when 'action' is " + action );
            }
            this.node = node;
            this.action = action;
            this.affiliate = affiliate;
            this.subscription = subscription;
        }

        static NodeOperation create( final Node node ) {
            return new NodeOperation( node, Action.CREATE, null, null );
        }
        static NodeOperation update( final Node node ) {
            return new NodeOperation( node, Action.UPDATE, null, null );
        }
        static NodeOperation remove( final Node node ) {
            return new NodeOperation( node, Action.REMOVE, null, null );
        }
        static NodeOperation createAffiliation( final Node node, final NodeAffiliate affiliate ) {
            return new NodeOperation( node, Action.CREATE_AFFILIATION, affiliate, null );
        }
        static NodeOperation updateAffiliation( final Node node, final NodeAffiliate affiliate ) {
            return new NodeOperation( node, Action.UPDATE_AFFILIATION, affiliate, null );
        }
        static NodeOperation removeAffiliation( final Node node, final NodeAffiliate affiliate ) {
            return new NodeOperation( node, Action.REMOVE_AFFILIATION, affiliate, null );
        }
        static NodeOperation createSubscription( final Node node, final NodeSubscription subscription ) {
            return new NodeOperation( node, Action.CREATE_SUBSCRIPTION, null, subscription);
        }
        static NodeOperation updateSubscription( final Node node, final NodeSubscription subscription ) {
            return new NodeOperation( node, Action.UPDATE_SUBSCRIPTION, null, subscription );
        }
        static NodeOperation removeSubscription( final Node node, final NodeSubscription subscription ) {
            return new NodeOperation( node, Action.REMOVE_SUBSCRIPTION, null, subscription );
        }
    }

    /**
     * Cache name for recently accessed published items.
     */
    private static final String ITEM_CACHE = "Published Items";

    /**
     * Cache for recently accessed published items.
     */
    // FIXME: the key value might have unforeseen duplicates, as it doesn't take the service into account! Multiple services could have equal keys!
    private final Cache<String, PublishedItem> itemCache = CacheFactory.createCache(ITEM_CACHE);

    /**
     * Cache name for recently accessed published items.
     */
    private static final String DEFAULT_CONF_CACHE = "Default Node Configurations";

    /**
     * Cache for default configurations
     */
    private final Cache<String, DefaultNodeConfiguration> defaultNodeConfigurationCache = CacheFactory.createCache(DEFAULT_CONF_CACHE);

    @Override
    public void initialize()
    {
        log.debug( "Initializing" );
    	try {
        	if (MAX_ITEMS_FLUSH > 0) {
        		TaskEngine.getInstance().schedule(new TimerTask() {
        			@Override
        			public void run() { flushPendingItems(false); } // this member only
        		}, Math.abs(prng.nextLong())%flushTimerDelay, flushTimerDelay);
        	}

    		// increase the timer delay when running in cluster mode
    		// because other members are also running the purge task
    		if (ClusterManager.isClusteringEnabled()) {
    			purgeTimerDelay = purgeTimerDelay*2;
    		}
    		TaskEngine.getInstance().schedule(new TimerTask() {
    			@Override
    			public void run() { purgeItems(); }
    		}, Math.abs(prng.nextLong())%purgeTimerDelay, purgeTimerDelay);
    		
    	} catch (Exception ex) {
    		log.error("Failed to initialize pubsub maintentence tasks", ex);
    	}

    }

    private void flushPendingNodes()
    {
        log.trace( "Flushing pending nodes (count: {})", nodesToProcess.size() );

        // TODO verify that this is thread-safe.
        final Iterator<List<NodeOperation>> iterator = nodesToProcess.values().iterator();
        while (iterator.hasNext()) {
            final List<NodeOperation> operations = iterator.next();
            operations.forEach( this::process );
            iterator.remove();
        }
    }

    private void flushPendingNodes( String serviceId )
    {
        log.trace( "Flushing pending nodes for service: {}", serviceId );

        // TODO verify that this is thread-safe (hint: it's not!)
        final Iterator<Map.Entry<Node.UniqueIdentifier, List<NodeOperation>>> iterator = nodesToProcess.entrySet().iterator();
        while (iterator.hasNext()) {
            final Map.Entry<Node.UniqueIdentifier,List<NodeOperation>> entry = iterator.next();
            if ( serviceId.equals( entry.getKey().getServiceId() ) )
            {
                entry.getValue().forEach( this::process );
                iterator.remove();
            }
        }
    }

    private void flushPendingNode( Node.UniqueIdentifier uniqueIdentifier )
    {
        log.trace( "Flushing pending node: {} for service: {}", uniqueIdentifier.getNodeId(), uniqueIdentifier.getServiceId() );

        // TODO verify if this is having the desired effect. - nodes could be in a hierarchy, which could warrant for flushing the entire tree.
        // TODO verify that this is thread-safe.
        nodesToProcess.computeIfPresent( uniqueIdentifier , ( key, operations ) -> {
            operations.forEach( this::process );
            // Returning null causes the mapping to removed from nodesToProcess.
            return null;
        } );
    }

    private void process( final NodeOperation operation ) {
        switch ( operation.action )
        {
            case CREATE:
                createNodeInDatabase( operation.node );
                break;

            case UPDATE:
                updateNodeInDatabase( operation.node );
                break;

            case REMOVE:
                removeNodeInDatabase( operation.node );
                break;

            case CREATE_AFFILIATION:
                createAffiliationInDatabase( operation.node, operation.affiliate );
                break;

            case UPDATE_AFFILIATION:
                updateAffiliationInDatabase( operation.node, operation.affiliate );
                break;

            case REMOVE_AFFILIATION:
                removeAffiliationInDatabase( operation.node, operation.affiliate );
                break;

            case CREATE_SUBSCRIPTION:
                createSubscriptionInDatabase( operation.node, operation.subscription );
                break;

            case UPDATE_SUBSCRIPTION:
                updateSubscriptionInDatabase( operation.node, operation.subscription );
                break;

            case REMOVE_SUBSCRIPTION:
                removeSubscriptionInDatabase( operation.subscription );
                break;

            default:
                throw new IllegalStateException(); // This indicates a bug in the implementation of this class.
        }
    }

    @Override
    public void createNode(Node node) {
        log.debug( "Creating node: {}", node.getUniqueIdentifier() );
        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );
        // Don't purge pending operations. It'd be odd for operations to already exist at this stage. It'd be possible for
        // a node to be recreated, which could mean that there's a DELETE. When there are other operations, the pre-'nodesToProcess'
        // behavior will kick in (which would presumably lead to database constraint-related exceptions).
        operations.add( NodeOperation.create( node ) );
    }

    /**
     * Creates and stores the node configuration in the database.
     *
     * @param node The newly created node.
     */
    private static void createNodeInDatabase(Node node) {
        log.trace( "Creating node: {} (write to database)", node.getUniqueIdentifier() );

        Connection con = null;
        PreparedStatement pstmt = null;
        boolean abortTransaction = false;
        try {
            con = DbConnectionManager.getTransactionConnection();
            pstmt = con.prepareStatement(ADD_NODE);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.setInt(3, (node.isCollectionNode() ? 0 : 1));
            pstmt.setString(4, StringUtils.dateToMillis(node.getCreationDate()));
            pstmt.setString(5, StringUtils.dateToMillis(node.getModificationDate()));
            pstmt.setString(6, node.getParent() != null ? encodeNodeID(node.getParent().getNodeID()) : null);
            pstmt.setInt(7, (node.isPayloadDelivered() ? 1 : 0));
            if (!node.isCollectionNode()) {
                pstmt.setInt(8, ((LeafNode) node).getMaxPayloadSize());
                pstmt.setInt(9, (((LeafNode) node).isPersistPublishedItems() ? 1 : 0));
                pstmt.setInt(10, ((LeafNode) node).getMaxPublishedItems());
            }
            else {
                pstmt.setInt(8, 0);
                pstmt.setInt(9, 0);
                pstmt.setInt(10, 0);
            }
            pstmt.setInt(11, (node.isNotifiedOfConfigChanges() ? 1 : 0));
            pstmt.setInt(12, (node.isNotifiedOfDelete() ? 1 : 0));
            pstmt.setInt(13, (node.isNotifiedOfRetract() ? 1 : 0));
            pstmt.setInt(14, (node.isPresenceBasedDelivery() ? 1 : 0));
            pstmt.setInt(15, (node.isSendItemSubscribe() ? 1 : 0));
            pstmt.setString(16, node.getPublisherModel().getName());
            pstmt.setInt(17, (node.isSubscriptionEnabled() ? 1 : 0));
            pstmt.setInt(18, (node.isSubscriptionConfigurationRequired() ? 1 : 0));
            pstmt.setString(19, node.getAccessModel().getName());
            pstmt.setString(20, node.getPayloadType());
            pstmt.setString(21, node.getBodyXSLT());
            pstmt.setString(22, node.getDataformXSLT());
            pstmt.setString(23, node.getCreator().toString());
            pstmt.setString(24, node.getDescription());
            pstmt.setString(25, node.getLanguage());
            pstmt.setString(26, node.getName());
            if (node.getReplyPolicy() != null) {
                pstmt.setString(27, node.getReplyPolicy().name());
            }
            else {
                pstmt.setString(27, null);
            }
            if (node.isCollectionNode()) {
                pstmt.setString(28, ((CollectionNode)node).getAssociationPolicy().name());
                pstmt.setInt(29, ((CollectionNode)node).getMaxLeafNodes());
            }
            else {
                pstmt.setString(28, null);
                pstmt.setInt(29, 0);
            }
            pstmt.executeUpdate();

            // Save associated JIDs and roster groups
            saveAssociatedElements(con, node);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
            abortTransaction = true;
        }
        finally {
            DbConnectionManager.closeStatement(pstmt);
            DbConnectionManager.closeTransactionConnection(con, abortTransaction);
        }
    }

    @Override
    public void updateNode(Node node) {
        log.debug( "Updating node: {}", node.getUniqueIdentifier() );

        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );

        // This update can replace any pending updates (since the last create/delete or affiliation change).
        final ListIterator<NodeOperation> iter = operations.listIterator( operations.size() );
        while ( iter.hasPrevious() ) {
            final NodeOperation operation = iter.previous();
            if ( operation.action.equals( NodeOperation.Action.UPDATE ) ) {
                iter.remove(); // This is replaced by the update that's being added.
            } else {
                break; // Operations that precede anything other than the last operations that are UPDATE shouldn't be replaced.
            }
        }
        operations.add( NodeOperation.update( node ));
    }

    /**
     * Updates the node configuration in the database.
     *
     * @param node The updated node.
     */
    private static void updateNodeInDatabase(Node node) {
        log.trace( "Updating node: {} (write to database)", node.getUniqueIdentifier() );

        Connection con = null;
        PreparedStatement pstmt = null;
        boolean abortTransaction = false;
        try {
            con = DbConnectionManager.getTransactionConnection();
            pstmt = con.prepareStatement(UPDATE_NODE);
            pstmt.setString(1, StringUtils.dateToMillis(node.getModificationDate()));
            pstmt.setString(2, node.getParent() != null ? encodeNodeID(node.getParent().getNodeID()) : null);
            pstmt.setInt(3, (node.isPayloadDelivered() ? 1 : 0));
            if (!node.isCollectionNode()) {
                pstmt.setInt(4, ((LeafNode) node).getMaxPayloadSize());
                pstmt.setInt(5, (((LeafNode) node).isPersistPublishedItems() ? 1 : 0));
                pstmt.setInt(6, ((LeafNode) node).getMaxPublishedItems());
            }
            else {
                pstmt.setInt(4, 0);
                pstmt.setInt(5, 0);
                pstmt.setInt(6, 0);
            }
            pstmt.setInt(7, (node.isNotifiedOfConfigChanges() ? 1 : 0));
            pstmt.setInt(8, (node.isNotifiedOfDelete() ? 1 : 0));
            pstmt.setInt(9, (node.isNotifiedOfRetract() ? 1 : 0));
            pstmt.setInt(10, (node.isPresenceBasedDelivery() ? 1 : 0));
            pstmt.setInt(11, (node.isSendItemSubscribe() ? 1 : 0));
            pstmt.setString(12, node.getPublisherModel().getName());
            pstmt.setInt(13, (node.isSubscriptionEnabled() ? 1 : 0));
            pstmt.setInt(14, (node.isSubscriptionConfigurationRequired() ? 1 : 0));
            pstmt.setString(15, node.getAccessModel().getName());
            pstmt.setString(16, node.getPayloadType());
            pstmt.setString(17, node.getBodyXSLT());
            pstmt.setString(18, node.getDataformXSLT());
            pstmt.setString(19, node.getDescription());
            pstmt.setString(20, node.getLanguage());
            pstmt.setString(21, node.getName());
            if (node.getReplyPolicy() != null) {
                pstmt.setString(22, node.getReplyPolicy().name());
            }
            else {
                pstmt.setString(22, null);
            }
            if (node.isCollectionNode()) {
                pstmt.setString(23, ((CollectionNode) node).getAssociationPolicy().name());
                pstmt.setInt(24, ((CollectionNode) node).getMaxLeafNodes());
            }
            else {
                pstmt.setString(23, null);
                pstmt.setInt(24, 0);
            }
            pstmt.setString(25, node.getService().getServiceID());
            pstmt.setString(26, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
            DbConnectionManager.fastcloseStmt(pstmt);

            // Remove existing JIDs associated with the the node
            pstmt = con.prepareStatement(DELETE_NODE_JIDS);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
            DbConnectionManager.fastcloseStmt(pstmt);

            // Remove roster groups associated with the the node being deleted
            pstmt = con.prepareStatement(DELETE_NODE_GROUPS);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();

            // Save associated JIDs and roster groups
            saveAssociatedElements(con, node);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
            abortTransaction = true;
        }
        finally {
            DbConnectionManager.closeStatement(pstmt);
            DbConnectionManager.closeTransactionConnection(con, abortTransaction);
        }
    }

    private static void saveAssociatedElements(Connection con, Node node) throws SQLException {
        log.trace( "Saving associates elements of node: {}", node.getUniqueIdentifier() );

        // Add new JIDs associated with the the node
        PreparedStatement pstmt = con.prepareStatement(ADD_NODE_JIDS);
        try {
            for (JID jid : node.getContacts()) {
                pstmt.setString(1, node.getService().getServiceID());
                pstmt.setString(2, encodeNodeID(node.getNodeID()));
                pstmt.setString(3, jid.toString());
                pstmt.setString(4, "contacts");
                pstmt.executeUpdate();
            }
            for (JID jid : node.getReplyRooms()) {
                pstmt.setString(1, node.getService().getServiceID());
                pstmt.setString(2, encodeNodeID(node.getNodeID()));
                pstmt.setString(3, jid.toString());
                pstmt.setString(4, "replyRooms");
                pstmt.executeUpdate();
            }
            for (JID jid : node.getReplyTo()) {
                pstmt.setString(1, node.getService().getServiceID());
                pstmt.setString(2, encodeNodeID(node.getNodeID()));
                pstmt.setString(3, jid.toString());
                pstmt.setString(4, "replyTo");
                pstmt.executeUpdate();
            }
            if (node.isCollectionNode()) {
                for (JID jid : ((CollectionNode) node).getAssociationTrusted()) {
                    pstmt.setString(1, node.getService().getServiceID());
                    pstmt.setString(2, encodeNodeID(node.getNodeID()));
                    pstmt.setString(3, jid.toString());
                    pstmt.setString(4, "associationTrusted");
                    pstmt.executeUpdate();
                }
            }
            DbConnectionManager.fastcloseStmt(pstmt);
            // Add new roster groups associated with the the node
            pstmt = con.prepareStatement(ADD_NODE_GROUPS);
            for (String groupName : node.getRosterGroupsAllowed()) {
                pstmt.setString(1, node.getService().getServiceID());
                pstmt.setString(2, encodeNodeID(node.getNodeID()));
                pstmt.setString(3, groupName);
                pstmt.executeUpdate();
            }
        }
        finally {
            DbConnectionManager.closeStatement(pstmt);
        }
    }

    @Override
    public void removeNode(Node node) {
        log.debug( "Removing node: {}", node.getUniqueIdentifier() );

        if ( node instanceof LeafNode ) {
            purgeNode( (LeafNode) node );
        }

        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );
        operations.clear(); // Any previously recorded, but as of yet unsaved operations, can be skipped.
        operations.add( NodeOperation.remove( node ));
    }

    /**
     * Removes the specified node from the DB.
     *
     * @param node The node that is being deleted.
     * @return true If the operation was successful.
     */
    private boolean removeNodeInDatabase(Node node) {
        log.trace( "Removing node: {} (write to database)", node.getUniqueIdentifier() );

        Connection con = null;
        PreparedStatement pstmt = null;
        boolean abortTransaction = false;
        try {
            con = DbConnectionManager.getTransactionConnection();
            // Remove the affiliate from the table of node affiliates
            pstmt = con.prepareStatement(DELETE_NODE);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
            DbConnectionManager.fastcloseStmt(pstmt);

            // Remove JIDs associated with the the node being deleted
            pstmt = con.prepareStatement(DELETE_NODE_JIDS);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
            DbConnectionManager.fastcloseStmt(pstmt);

            // Remove roster groups associated with the the node being deleted
            pstmt = con.prepareStatement(DELETE_NODE_GROUPS);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
            DbConnectionManager.fastcloseStmt(pstmt);

            // Remove published items of the node being deleted
			if (node instanceof LeafNode)
			{
				purgeNode((LeafNode) node, con);
			}

            // Remove all affiliates from the table of node affiliates
            pstmt = con.prepareStatement(DELETE_AFFILIATIONS);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
            DbConnectionManager.fastcloseStmt(pstmt);

            // Remove users that were subscribed to the node
            pstmt = con.prepareStatement(DELETE_SUBSCRIPTIONS);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
            abortTransaction = true;
        }
        finally {
            DbConnectionManager.closeStatement(pstmt);
            DbConnectionManager.closeTransactionConnection(con, abortTransaction);
        }
        return !abortTransaction;
    }

    @Override
    public void loadNodes(PubSubService service) {
        log.debug( "Loading nodes for service: {}", service.getServiceID() );

        // Make sure that all changes to nodes have been written to the database
        // before the nodes are retrieved.
        flushPendingNodes( service.getServiceID() );

        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        Map<String, Node> nodes = new HashMap<>();
        try {
            con = DbConnectionManager.getConnection();
            // Get all non-leaf nodes (to ensure parent nodes are loaded before their children)
			pstmt = con.prepareStatement(LOAD_NODES);
            pstmt.setString(1, service.getServiceID());
            rs = pstmt.executeQuery();
            
            Map<String, String> parentMappings = new HashMap<>();
            
            // Rebuild loaded non-leaf nodes
            while(rs.next()) {
                loadNode(service, nodes, parentMappings, rs);
            }
            DbConnectionManager.fastcloseStmt(rs, pstmt);

            if (nodes.size() == 0) {
            	log.info("No nodes found in pubsub for service {}", service.getServiceID() );
            	return;
            }
            
            for (Map.Entry<String, String> entry : parentMappings.entrySet()) {
            	Node child = nodes.get(entry.getKey());
            	CollectionNode parent = (CollectionNode) nodes.get(entry.getValue());
            	
            	if (parent == null) {
            		log.error("Could not find parent node " + entry.getValue() + " for node " + entry.getKey());
            	}
            	else {
            		child.changeParent(parent);
            	}
            }
            // Get JIDs associated with all nodes
            pstmt = con.prepareStatement(LOAD_NODES_JIDS);
            pstmt.setString(1, service.getServiceID());
            rs = pstmt.executeQuery();
            // Add to each node the associated JIDs
            while(rs.next()) {
                loadAssociatedJIDs(nodes, rs);
            }
            DbConnectionManager.fastcloseStmt(rs, pstmt);

            // Get roster groups associateds with all nodes
            pstmt = con.prepareStatement(LOAD_NODES_GROUPS);
            pstmt.setString(1, service.getServiceID());
            rs = pstmt.executeQuery();
            // Add to each node the associated Groups
            while(rs.next()) {
                loadAssociatedGroups(nodes, rs);
            }
            DbConnectionManager.fastcloseStmt(rs, pstmt);

            // Get affiliations of all nodes
            pstmt = con.prepareStatement(LOAD_AFFILIATIONS);
            pstmt.setString(1, service.getServiceID());
            rs = pstmt.executeQuery();
            // Add to each node the correspondiding affiliates
            while(rs.next()) {
                loadAffiliations(nodes, rs);
            }
            DbConnectionManager.fastcloseStmt(rs, pstmt);

            // Get subscriptions to all nodes
            pstmt = con.prepareStatement(LOAD_SUBSCRIPTIONS);
            pstmt.setString(1, service.getServiceID());
            rs = pstmt.executeQuery();
            // Add to each node the correspondiding subscriptions
            while(rs.next()) {
                loadSubscriptions(service, nodes, rs);
            }
            DbConnectionManager.fastcloseStmt(rs, pstmt);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }

        for (Node node : nodes.values()) {
            // Set now that the node is persistent in the database. Note: We need to
            // set this now since otherwise the node's affiliations will be saved to the database
            // "again" while adding them to the node!
            node.setSavedToDB(true);
            // Add the node to the service
            service.addNode(node);
        }
    }

    @Override
	public void loadNode(PubSubService service, String nodeId)
	{
	    final Node.UniqueIdentifier uniqueIdentifier = new Node.UniqueIdentifier( service.getServiceID(), nodeId );
        log.debug( "Loading node: {}", uniqueIdentifier );

        // Make sure that all changes to nodes have been written to the database
        // before the nodes are retrieved.
	    flushPendingNode( uniqueIdentifier );

        Connection con = null;
		PreparedStatement pstmt = null;
		ResultSet rs = null;
		Map<String, Node> nodes = new HashMap<>();
		try
		{
			con = DbConnectionManager.getConnection();
			// Get all non-leaf nodes (to ensure parent nodes are loaded before
			// their children)
			pstmt = con.prepareStatement(LOAD_NODE);
			pstmt.setString(1, service.getServiceID());
			pstmt.setString(2, nodeId);
			rs = pstmt.executeQuery();
			Map<String, String> parentMapping = new HashMap<>();
			
			// Rebuild loaded non-leaf nodes
			if (rs.next())
			{
				loadNode(service, nodes, parentMapping, rs);
			}
			DbConnectionManager.fastcloseStmt(rs, pstmt);
			String parentId = parentMapping.get(nodeId);
			
			if (parentId != null) {
				CollectionNode parent = (CollectionNode) service.getNode(parentId);
				
				if (parent == null) {
            		log.error("Could not find parent node " + parentId + " for node " + uniqueIdentifier);
				}
				else {
					nodes.get(nodeId).changeParent(parent);
				}
			}
				
			// Get JIDs associated with all nodes
			pstmt = con.prepareStatement(LOAD_NODE_JIDS);
			pstmt.setString(1, service.getServiceID());
			pstmt.setString(2, nodeId);
			rs = pstmt.executeQuery();
			// Add to each node the associated JIDs
			while (rs.next())
			{
				loadAssociatedJIDs(nodes, rs);
			}
			DbConnectionManager.fastcloseStmt(rs, pstmt);

			// Get roster groups associated with all nodes
			pstmt = con.prepareStatement(LOAD_NODE_GROUPS);
			pstmt.setString(1, service.getServiceID());
			pstmt.setString(2, nodeId);
			rs = pstmt.executeQuery();
			// Add to each node the associated Groups
			while (rs.next())
			{
				loadAssociatedGroups(nodes, rs);
			}
			DbConnectionManager.fastcloseStmt(rs, pstmt);

			// Get affiliations of all nodes
			pstmt = con.prepareStatement(LOAD_NODE_AFFILIATIONS);
			pstmt.setString(1, service.getServiceID());
			pstmt.setString(2, nodeId);
			rs = pstmt.executeQuery();
			// Add to each node the corresponding affiliates
			while (rs.next())
			{
				loadAffiliations(nodes, rs);
			}
			DbConnectionManager.fastcloseStmt(rs, pstmt);

			// Get subscriptions to all nodes
			pstmt = con.prepareStatement(LOAD_NODE_SUBSCRIPTIONS);
			pstmt.setString(1, service.getServiceID());
			pstmt.setString(2, nodeId);
			rs = pstmt.executeQuery();
			// Add to each node the corresponding subscriptions
			while (rs.next())
			{
				loadSubscriptions(service, nodes, rs);
			}
			DbConnectionManager.fastcloseStmt(rs, pstmt);
		}
		catch (SQLException sqle)
		{
			log.error(sqle.getMessage(), sqle);
		}
		finally
		{
			DbConnectionManager.closeConnection(rs, pstmt, con);
		}

		for (Node node : nodes.values())
		{
			// Set now that the node is persistent in the database. Note: We
			// need to
			// set this now since otherwise the node's affiliations will be
			// saved to the database
			// "again" while adding them to the node!
			node.setSavedToDB(true);
			// Add the node to the service
			service.addNode(node);
		}
	}

    private void loadNode(PubSubService service, Map<String, Node> loadedNodes, Map<String, String> parentMappings, ResultSet rs) {
        Node node;
        try {
            String nodeID = decodeNodeID(rs.getString(1));
            boolean leaf = rs.getInt(2) == 1;
            String parent = decodeNodeID(rs.getString(5));
            JID creator = new JID(rs.getString(22));
            
            if (parent != null) {
            	parentMappings.put(nodeID, parent);
            }

            if (leaf) {
                // Retrieving a leaf node
                node = new LeafNode(service, null, nodeID, creator);
            }
            else {
                // Retrieving a collection node
                node = new CollectionNode(service, null, nodeID, creator);
            }
            node.setCreationDate(new Date(Long.parseLong(rs.getString(3).trim())));
            node.setModificationDate(new Date(Long.parseLong(rs.getString(4).trim())));
            node.setPayloadDelivered(rs.getInt(6) == 1);
            if (leaf) {
                ((LeafNode) node).setMaxPayloadSize(rs.getInt(7));
                ((LeafNode) node).setPersistPublishedItems(rs.getInt(8) == 1);
                ((LeafNode) node).setMaxPublishedItems(rs.getInt(9));
                ((LeafNode) node).setSendItemSubscribe(rs.getInt(14) == 1);
            }
            node.setNotifiedOfConfigChanges(rs.getInt(10) == 1);
            node.setNotifiedOfDelete(rs.getInt(11) == 1);
            node.setNotifiedOfRetract(rs.getInt(12) == 1);
            node.setPresenceBasedDelivery(rs.getInt(13) == 1);
            node.setPublisherModel(PublisherModel.valueOf(rs.getString(15)));
            node.setSubscriptionEnabled(rs.getInt(16) == 1);
            node.setSubscriptionConfigurationRequired(rs.getInt(17) == 1);
            node.setAccessModel(AccessModel.valueOf(rs.getString(18)));
            node.setPayloadType(rs.getString(19));
            node.setBodyXSLT(rs.getString(20));
            node.setDataformXSLT(rs.getString(21));
            node.setDescription(rs.getString(23));
            node.setLanguage(rs.getString(24));
            node.setName(rs.getString(25));
            if (rs.getString(26) != null) {
                node.setReplyPolicy(Node.ItemReplyPolicy.valueOf(rs.getString(26)));
            }
            if (!leaf) {
                ((CollectionNode) node).setAssociationPolicy(
                        CollectionNode.LeafNodeAssociationPolicy.valueOf(rs.getString(27)));
                ((CollectionNode) node).setMaxLeafNodes(rs.getInt(28));
            }

            // Add the load to the list of loaded nodes
            loadedNodes.put(node.getNodeID(), node);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
    }

    private void loadAssociatedJIDs(Map<String, Node> nodes, ResultSet rs) {
        try {
            String nodeID = decodeNodeID(rs.getString(1));
            Node node = nodes.get(nodeID);
            if (node == null) {
                log.warn("JID associated to a non-existent node: " + nodeID);
                return;
            }
            JID jid = new JID(rs.getString(2));
            String associationType = rs.getString(3);
            if ("contacts".equals(associationType)) {
                node.addContact(jid);
            }
            else if ("replyRooms".equals(associationType)) {
                node.addReplyRoom(jid);
            }
            else if ("replyTo".equals(associationType)) {
                node.addReplyTo(jid);
            }
            else if ("associationTrusted".equals(associationType)) {
                ((CollectionNode) node).addAssociationTrusted(jid);
            }
        }
        catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }
    }

    private void loadAssociatedGroups(Map<String, Node> nodes, ResultSet rs) {
        try {
            String nodeID = decodeNodeID(rs.getString(1));
            Node node = nodes.get(nodeID);
            if (node == null) {
                log.warn("Roster Group associated to a non-existent node: " + nodeID);
                return;
            }
            node.addAllowedRosterGroup(rs.getString(2));
        }
        catch (SQLException ex) {
            log.error(ex.getMessage(), ex);
        }
    }

    private void loadAffiliations(Map<String, Node> nodes, ResultSet rs) {
        try {
            String nodeID = decodeNodeID(rs.getString(1));
            Node node = nodes.get(nodeID);
            if (node == null) {
                log.warn("Affiliations found for a non-existent node: " + nodeID);
                return;
            }
            NodeAffiliate affiliate = new NodeAffiliate(node, new JID(rs.getString(2)));
            affiliate.setAffiliation(NodeAffiliate.Affiliation.valueOf(rs.getString(3)));
            node.addAffiliate(affiliate);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
    }

    @Override
	public void loadSubscription(PubSubService service, Node node, String subId)
	{
	    flushPendingNode( new Node.UniqueIdentifier( service.getServiceID(), node.getNodeID() ) );

	    Connection con = null;
		PreparedStatement pstmt = null;
		ResultSet rs = null;
		Map<String, Node> nodes = new HashMap<>();
		nodes.put(node.getNodeID(), node);

		try
		{
			con = DbConnectionManager.getConnection();

			// Get subscriptions to all nodes
			pstmt = con.prepareStatement(LOAD_NODE_SUBSCRIPTION);
			pstmt.setString(1, service.getServiceID());
			pstmt.setString(2, node.getNodeID());
			pstmt.setString(3, subId);
			rs = pstmt.executeQuery();

			// Add to each node the corresponding subscription
			if (rs.next())
			{
				loadSubscriptions(service, nodes, rs);
			}
		}
		catch (SQLException sqle)
		{
			log.error(sqle.getMessage(), sqle);
		}
		finally
		{
			DbConnectionManager.closeConnection(rs, pstmt, con);
		}
	}

    private void loadSubscriptions(PubSubService service, Map<String, Node> nodes, ResultSet rs) {
        try {
            String nodeID = decodeNodeID(rs.getString(1));
            Node node = nodes.get(nodeID);
            if (node == null) {
                log.warn("Subscription found for a non-existent node: " + nodeID);
                return;
            }
            String subID = rs.getString(2);
            JID subscriber = new JID(rs.getString(3));
            JID owner = new JID(rs.getString(4));
            if (node.getAffiliate(owner) == null) {
                log.warn("Subscription found for a non-existent affiliate: " + owner +
                        " in node: " + node.getUniqueIdentifier());
                return;
            }
            NodeSubscription.State state = NodeSubscription.State.valueOf(rs.getString(5));
			NodeSubscription subscription = new NodeSubscription(node, owner, subscriber, state, subID);
            subscription.setShouldDeliverNotifications(rs.getInt(6) == 1);
            subscription.setUsingDigest(rs.getInt(7) == 1);
            subscription.setDigestFrequency(rs.getInt(8));
            if (rs.getString(9) != null) {
                subscription.setExpire(new Date(Long.parseLong(rs.getString(9).trim())));
            }
            subscription.setIncludingBody(rs.getInt(10) == 1);
            subscription.setPresenceStates(decodeWithComma(rs.getString(11)));
            subscription.setType(NodeSubscription.Type.valueOf(rs.getString(12)));
            subscription.setDepth(rs.getInt(13));
            subscription.setKeyword(rs.getString(14));
            // Indicate the subscription that is has already been saved to the database
            subscription.setSavedToDB(true);
            node.addSubscription(subscription);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
    }

    @Override
    public void createAffiliation(Node node, NodeAffiliate affiliate)
    {
        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );
        final NodeOperation operation = NodeOperation.createAffiliation( node, affiliate );
        operations.add( operation );
    }

    @Override
    public void updateAffiliation(Node node, NodeAffiliate affiliate)
    {
        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );
        // This affiliation update can replace any pending updates of the same affiliate (since the last create/delete of the node or affiliation change of this affiliate to the node).
        final ListIterator<NodeOperation> iter = operations.listIterator( operations.size() );
        while ( iter.hasPrevious() ) {
            final NodeOperation op = iter.previous();
            if ( op.action.equals( NodeOperation.Action.UPDATE_AFFILIATION ) ) {
                if ( affiliate.getJID().equals( op.affiliate.getJID() ) ) {
                    iter.remove(); // This is replaced by the update that's being added.
                }
            } else {
                break; // Operations that precede anything other than the last operations that are UPDATE_AFFILIATE shouldn't be replaced.
            }
        }

        final NodeOperation operation = NodeOperation.updateAffiliation( node, affiliate );
        operations.add( operation );
    }

    /**
     * Update the DB with the new affiliation of the user in the node.
     *
     * @param node      The node where the affiliation of the user was updated.
     * @param affiliate The new affiliation of the user in the node.
     * @param create    True if this is a new affiliate.
     * @deprecated replaced by {@link #createAffiliation(Node, NodeAffiliate)} and {@link #updateAffiliation(Node, NodeAffiliate)}
     */
    @Deprecated
    public void saveAffiliation(Node node, NodeAffiliate affiliate, boolean create) {
        if (create) {
            createAffiliation( node, affiliate );
        } else {
            updateAffiliation( node, affiliate );
        }
    }

    // Add the user to the generic affiliations table
    private static void createAffiliationInDatabase(Node node, NodeAffiliate affiliate) {
        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(ADD_AFFILIATION);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.setString(3, affiliate.getJID().toString());
            pstmt.setString(4, affiliate.getAffiliation().name());
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }

    // Update the affiliate's data in the backend store
    private static void updateAffiliationInDatabase(Node node, NodeAffiliate affiliate) {
        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(UPDATE_AFFILIATION);
            pstmt.setString(1, affiliate.getAffiliation().name());
            pstmt.setString(2, node.getService().getServiceID());
            pstmt.setString(3, encodeNodeID(node.getNodeID()));
            pstmt.setString(4, affiliate.getJID().toString());
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }

    @Override
    public void removeAffiliation(Node node, NodeAffiliate affiliate) {
        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );

        // This affiliation removal can replace any pending creation, update or delete of the same affiliate (since the last create/delete of the node or affiliation change of this affiliate to the node).
        final ListIterator<NodeOperation> iter = operations.listIterator( operations.size() );
        while ( iter.hasPrevious() ) {
            final NodeOperation operation = iter.previous();
            if ( Arrays.asList( NodeOperation.Action.CREATE_AFFILIATION, NodeOperation.Action.UPDATE_AFFILIATION, NodeOperation.Action.REMOVE_AFFILIATION ).contains( operation.action ) ) {
                if ( affiliate.getJID().equals( operation.affiliate.getJID() ) ) {
                    iter.remove(); // This is replaced by the update that's being added.
                }
            } else {
                break; // Operations that precede anything other than the last operations that are affiliate changes shouldn't be replaced.
            }
        }
        operations.add( NodeOperation.removeAffiliation( node, affiliate ) );
    }

    /**
     * Removes the affiliation and subsription state of the user from the DB.
     *
     * @param node      The node where the affiliation of the user was updated.
     * @param affiliate The existing affiliation and subsription state of the user in the node.
     */
    private static void removeAffiliationInDatabase(Node node, NodeAffiliate affiliate) {
        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            // Remove the affiliate from the table of node affiliates
            pstmt = con.prepareStatement(DELETE_AFFILIATION);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.setString(3, affiliate.getJID().toString());
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }

    @Override
    public void createSubscription(Node node, NodeSubscription subscription) {
        log.debug( "Creating node subscription: {} {}", node.getUniqueIdentifier(), subscription.getID() );

        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );
        final NodeOperation operation = NodeOperation.createSubscription( node, subscription );
        operations.add( operation );
    }

    @Override
    public void updateSubscription(Node node, NodeSubscription subscription) {
        log.debug( "Updating node subscription: {} {}", node.getUniqueIdentifier(), subscription.getID() );
        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( node.getUniqueIdentifier(), id -> new ArrayList<>() );

        // This subscription update can replace any pending updates of the same subscription (since the last create/delete of the node or subscription change of this affiliate to the node).
        final ListIterator<NodeOperation> iter = operations.listIterator( operations.size() );
        while ( iter.hasPrevious() ) {
            final NodeOperation op = iter.previous();
            if ( op.action.equals( NodeOperation.Action.UPDATE_SUBSCRIPTION ) ) {
                if ( subscription.getID().equals( op.subscription.getID() ) ) {
                    iter.remove(); // This is replaced by the update that's being added.
                }
            } else {
                break; // Operations that precede anything other than the last operations that are UPDATE_AFFILIATE shouldn't be replaced.
            }
        }

        final NodeOperation operation = NodeOperation.updateSubscription( node, subscription );
        operations.add( operation );
    }

    /**
     * Updates the DB with the new subscription of the user to the node.
     *
     * @param node      The node where the user has subscribed to.
     * @param subscription The new subscription of the user to the node.
     * @param create    True if this is a new affiliate.
     * @deprecated Replaced by {@link #createSubscription(Node, NodeSubscription)} and {@link #updateSubscription(Node, NodeSubscription)}
     */
    @Deprecated
    public void saveSubscription(Node node, NodeSubscription subscription, boolean create) {
        if (create) {
            createSubscription( node, subscription );
        } else {
            updateSubscription( node, subscription );
        }
    }

    /**
     * Updates the DB with the new subscription of the user to the node.
     *
     * @param node      The node where the user has subscribed to.
     * @param subscription The new subscription of the user to the node.
     */
    private static void createSubscriptionInDatabase(Node node, NodeSubscription subscription) {
        log.trace( "Creating node subscription: {} {} (write to database)", node.getUniqueIdentifier(), subscription.getID() );
        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            // Add the subscription of the user to the database
            pstmt = con.prepareStatement(ADD_SUBSCRIPTION);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            pstmt.setString(3, subscription.getID());
            pstmt.setString(4, subscription.getJID().toString());
            pstmt.setString(5, subscription.getOwner().toString());
            pstmt.setString(6, subscription.getState().name());
            pstmt.setInt(7, (subscription.shouldDeliverNotifications() ? 1 : 0));
            pstmt.setInt(8, (subscription.isUsingDigest() ? 1 : 0));
            pstmt.setInt(9, subscription.getDigestFrequency());
            Date expireDate = subscription.getExpire();
            if (expireDate == null) {
                pstmt.setString(10, null);
            }
            else {
                pstmt.setString(10, StringUtils.dateToMillis(expireDate));
            }
            pstmt.setInt(11, (subscription.isIncludingBody() ? 1 : 0));
            pstmt.setString(12, encodeWithComma(subscription.getPresenceStates()));
            pstmt.setString(13, subscription.getType().name());
            pstmt.setInt(14, subscription.getDepth());
            pstmt.setString(15, subscription.getKeyword());
            pstmt.executeUpdate();
            // Indicate the subscription that is has been saved to the database
            subscription.setSavedToDB(true);
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }

    /**
     * Updates the DB with the new subscription of the user to the node.
     *
     * @param node      The node where the user has subscribed to.
     * @param subscription The new subscription of the user to the node.
     */
    private static void updateSubscriptionInDatabase(Node node, NodeSubscription subscription) {
        log.trace( "Updating node subscription: {} {} (write to database)", node.getUniqueIdentifier(), subscription.getID() );
        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            if (NodeSubscription.State.none == subscription.getState()) {
                // Remove the subscription of the user from the table
                pstmt = con.prepareStatement(DELETE_SUBSCRIPTION);
                pstmt.setString(1, node.getService().getServiceID());
                pstmt.setString(2, encodeNodeID(node.getNodeID()));
                pstmt.setString(2, subscription.getID());
                pstmt.executeUpdate();
            }
            else {
                // Update the subscription of the user in the backend store
                pstmt = con.prepareStatement(UPDATE_SUBSCRIPTION);
                pstmt.setString(1, subscription.getOwner().toString());
                pstmt.setString(2, subscription.getState().name());
                pstmt.setInt(3, (subscription.shouldDeliverNotifications() ? 1 : 0));
                pstmt.setInt(4, (subscription.isUsingDigest() ? 1 : 0));
                pstmt.setInt(5, subscription.getDigestFrequency());
                Date expireDate = subscription.getExpire();
                if (expireDate == null) {
                    pstmt.setString(6, null);
                }
                else {
                    pstmt.setString(6, StringUtils.dateToMillis(expireDate));
                }
                pstmt.setInt(7, (subscription.isIncludingBody() ? 1 : 0));
                pstmt.setString(8, encodeWithComma(subscription.getPresenceStates()));
                pstmt.setString(9, subscription.getType().name());
                pstmt.setInt(10, subscription.getDepth());
                pstmt.setString(11, subscription.getKeyword());
                pstmt.setString(12, node.getService().getServiceID());
                pstmt.setString(13, encodeNodeID(node.getNodeID()));
                pstmt.setString(14, subscription.getID());
                pstmt.executeUpdate();
            }
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }

    @Override
    public void removeSubscription(NodeSubscription subscription) {
        log.debug( "Removing node subscription: {} {}", subscription.getNode().getUniqueIdentifier(), subscription.getID() );

        final List<NodeOperation> operations = nodesToProcess.computeIfAbsent( subscription.getNode().getUniqueIdentifier(), id -> new ArrayList<>() );

        // This subscription removal can replace any pending creation, update or delete of the same subscription (since the last create/delete of the node or subscription change of this subscription to the node).
        final ListIterator<NodeOperation> iter = operations.listIterator( operations.size() );
        while ( iter.hasPrevious() ) {
            final NodeOperation operation = iter.previous();
            if ( Arrays.asList( NodeOperation.Action.CREATE_SUBSCRIPTION, NodeOperation.Action.UPDATE_SUBSCRIPTION, NodeOperation.Action.REMOVE_SUBSCRIPTION ).contains( operation.action ) ) {
                if ( subscription.getID().equals( operation.subscription.getID() ) ) {
                    iter.remove(); // This is replaced by the update that's being added.
                }
            } else {
                break; // Operations that precede anything other than the last operations that are subscription changes shouldn't be replaced.
            }
        }
        operations.add( NodeOperation.removeSubscription( subscription.getNode(), subscription ) );
    }

    /**
     * Removes the subscription of the user from the DB.
     *
     * @param subscription The existing subsription of the user to the node.
     */
    private static void removeSubscriptionInDatabase(NodeSubscription subscription) {
        log.trace( "Removing node subscription: {} {} (write to database)", subscription.getNode().getUniqueIdentifier(), subscription.getID() );

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            // Remove the affiliate from the table of node affiliates
            pstmt = con.prepareStatement(DELETE_SUBSCRIPTION);
            pstmt.setString(1, subscription.getNode().getService().getServiceID());
            pstmt.setString(2, encodeNodeID(subscription.getNode().getNodeID()));
            pstmt.setString(3, subscription.getID());
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
    }

    @Override
    public void savePublishedItem(PublishedItem item) {
        log.debug( "Saving published item {} {}", item.getNode().getUniqueIdentifier(), item.getID() );

        savePublishedItem(new RetryWrapper(item));
    }

    /**
     * Creates and stores the published item in the database. 
     * @param wrapper The published item, wrapped for retry
     */
    private void savePublishedItem(RetryWrapper wrapper) {
    	boolean firstPass = (wrapper.getRetryCount() == 0);
    	PublishedItem item = wrapper.get();
		String itemKey = item.getItemKey();
		itemCache.put(itemKey, item);
		log.debug("Added new (inbound) item to cache");
        synchronized (itemsPending) {
    		RetryWrapper itemToReplace = itemsPending.remove(itemKey);
    		if (itemToReplace != null) {
                itemsToAdd.remove(itemToReplace); // remove duplicate from itemsToAdd linked list
    		}
    		if (firstPass) {
    		    itemsToAdd.addLast(wrapper);
            } else {
                itemsToAdd.addFirst(wrapper);
            }
    		itemsPending.put(itemKey, wrapper);
        }
        // skip the flush step if this is a retry attempt
		if (firstPass && itemsPending.size() > MAX_ITEMS_FLUSH) {
			TaskEngine.getInstance().submit(new Runnable() {
				@Override
				public void run() { flushPendingItems(false); }
			});
		}
    }
    
    /**
     * This class is used internally to wrap PublishedItems. It adds
     * a retry counter for the persistence exception handling logic.
     */
    private static class RetryWrapper {
    	private PublishedItem item;
        private volatile transient int retryCount = 0;
    	public RetryWrapper(PublishedItem item) { this.item = item; }
    	public PublishedItem get() { return item; }
    	public int getRetryCount() { return retryCount; }
    	public int nextRetry() { return ++retryCount; }
    }

    @Override
    public void flushPendingItems( Node.UniqueIdentifier nodeUniqueId )
    {
        flushPendingItems(nodeUniqueId, ClusterManager.isClusteringEnabled());
    }

    @Override
	public void flushPendingItems()
    {
        flushPendingItems(ClusterManager.isClusteringEnabled());
    }

    @Override
    public void flushPendingItems(Node.UniqueIdentifier nodeUniqueId, boolean sendToCluster)
    {
        // forward to other cluster members and wait for response
        if (sendToCluster) {
            CacheFactory.doSynchronousClusterTask(new FlushTask(nodeUniqueId), false);
        }

        // TODO: figure out if it's required to first flush pending nodes, cluster-wide, synchronously, before flushing items.
        flushPendingNode(nodeUniqueId);

        if (itemsToAdd.isEmpty() && itemsToDelete.isEmpty()) {
            return;	 // nothing to do for this cluster member
        }

        List<RetryWrapper> addList;
        List<PublishedItem> delList;

        // Swap pending items so we can parse and save the contents from this point in time
        // while not blocking new entries from being cached.
        synchronized(itemsPending)
        {
            // find items for node.

            // Split the to-do list in two parts: one that contains items for the node of interest, and the rest.
            final Map<Boolean, List<RetryWrapper>> partsToAdd = itemsToAdd.stream().collect(
                    Collectors.partitioningBy( retryWrapper -> nodeUniqueId.equals( retryWrapper.item.getNode().getUniqueIdentifier() ) )
            );
            addList = new ArrayList<>( partsToAdd.get( true ) ); // All elements that match must be processed.
            itemsToAdd.retainAll( partsToAdd.get(false) ); // Non-matching elements remain on the to-do list.

            // Split the to-do list in two parts: one that contains items for the node of interest, and the rest.
            final Map<Boolean, List<PublishedItem>> partsToDelete = itemsToDelete.stream().collect(
                    Collectors.partitioningBy( publishedItem -> nodeUniqueId.equals( publishedItem.getNode().getUniqueIdentifier() ) )
            );
            delList = new ArrayList<>( partsToDelete.get( true ) ); // All elements that match must be processed.
            itemsToDelete.retainAll( partsToDelete.get(false) ); // Non-matching elements remain on the to-do list.

            // Ensure pending items are available via the item read cache;
            // this allows the item(s) to be fetched by other request threads
            // while being written to the DB from this thread
            // TODO Determine if this works as intended when items are being queued for adding as well as removal.
            int copied = 0;
            for (final RetryWrapper itemToAdd : itemsToAdd) {
                final String key = itemToAdd.get().getItemKey();
                if (!itemCache.containsKey(key)) {
                    itemsPending.remove( key );
                    itemCache.put(key, itemToAdd.item);
                    copied++;
                }
            }
            if (log.isDebugEnabled() && copied > 0) {
                log.debug("Added " + copied + " pending items to published item cache");
            }
        }

        flushPendingItemsToDatabase( addList, delList );
    }

    @Override
    public void flushPendingItems(boolean sendToCluster)
    {
		// forward to other cluster members and wait for response
		if (sendToCluster) {
            CacheFactory.doSynchronousClusterTask(new FlushTask(), false);
        }

		if (itemsToAdd.isEmpty() && itemsToDelete.isEmpty() ) {
        	return;	 // nothing to do for this cluster member
        }

        // TODO: figure out if it's required to first flush pending nodes, cluster-wide, synchronously, before flushing items.
        flushPendingNodes();

        List<RetryWrapper> addList;
        List<PublishedItem> delList;

    	// Swap pending items so we can parse and save the contents from this point in time
    	// while not blocking new entries from being cached.
    	synchronized(itemsPending) 
    	{
    		addList = new ArrayList<>( itemsToAdd );
    		delList = new ArrayList<>( itemsToDelete );

    		itemsToAdd = new ConcurrentLinkedDeque<>();
    		itemsToDelete = new ConcurrentLinkedDeque<>();

    		// Ensure pending items are available via the item read cache;
    		// this allows the item(s) to be fetched by other request threads
    		// while being written to the DB from this thread
            // TODO Determine if this works as intended when items are being queued for adding as well as removal.
    		int copied = 0;
    		for (String key : itemsPending.keySet()) {
    			if (!itemCache.containsKey(key)) {
    				itemCache.put(key, (itemsPending.get(key)).get());
    				copied++;
    			}
    		}
    		if (log.isDebugEnabled() && copied > 0) {
    			log.debug("Added " + copied + " pending items to published item cache");
    		}
    		itemsPending.clear();
    	}

        flushPendingItemsToDatabase( addList, delList );
	}

	private void flushPendingItemsToDatabase( final List<RetryWrapper> addList, final List<PublishedItem> delList )
    {
        // Note that we now make multiple attempts to write cached items to the DB:
        //   1) insert all pending items in a single batch
        //   2) if the batch insert fails, retry by inserting each item separately
        //   3) if a given item cannot be written, return it to the pending write cache
        // By default step 3 will be tried once per item, but this can be configured
        // (or disabled) using the "xmpp.pubsub.item.retry" property. In the event of
        // a transaction rollback, items that could not be written to the database
        // will be returned to the pending item write cache.
        Connection con = null;
        boolean rollback = false;
        try {
            con = DbConnectionManager.getTransactionConnection();
            writePendingItems(con, addList, delList);
        } catch (SQLException se) {
            // TODO it's suspiscous that the delList isn't rolled back. Determine if this is a bug!
            log.error("Failed to flush pending items; initiating rollback", se);
            // return new items to the write cache
            addList.forEach( this::savePublishedItem );
            rollback = true;
        } finally {
            DbConnectionManager.closeTransactionConnection(con, rollback);
        }
    }

    /**
     * Loop through the lists of added and deleted items and write to the database
     * @param con
     * @param addList
     * @param delList
     * @throws SQLException
     */
	private void writePendingItems(Connection con, List<RetryWrapper> addList, List<PublishedItem> delList) throws SQLException
	{
        // is there anything to do?
        if (addList.isEmpty() && delList.isEmpty() ) { return; }

    	if (log.isDebugEnabled()) {
    		log.debug("Flush pending items to database");
    	}

        // ensure there are no duplicates by deleting before adding
    	delList.addAll( addList.stream().map( RetryWrapper::get ).collect( Collectors.toList()) );

        // delete first (to remove possible duplicates), then add new items
        PreparedStatement pstmt = null;
        try {
            pstmt = con.prepareStatement(DELETE_ITEM);
            boolean hasBatchItems = false;
            for ( final PublishedItem item : delList )
            {
                hasBatchItems = true;
                pstmt.setString(1, item.getNode().getService().getServiceID());
                pstmt.setString(2, encodeNodeID(item.getNode().getNodeID()));
                pstmt.setString(3, item.getID());
                pstmt.addBatch();
            }
            if (hasBatchItems) pstmt.executeBatch();
        } catch (SQLException ex) {
            log.error("Failed to delete published item(s) from DB", ex);
            // do not re-throw here; continue with insert operation if possible
        } finally {
            DbConnectionManager.closeStatement(pstmt);
        }

        try {
            // first try to add the pending items as a batch
        	writePendingItems(con, addList, true);
        } catch (SQLException ex) {
        	// retry each item individually rather than rolling back
        	writePendingItems(con, addList, false);
        }
    }

	/**
	 * Execute JDBC calls (optionally via batch) to persist the given published items
	 * @param con
	 * @param addItems
	 * @param batch
	 * @throws SQLException
	 */
	private void writePendingItems(Connection con, List<RetryWrapper> addItems, boolean batch)  throws SQLException
	{
		if (addItems == null || addItems.isEmpty()) { return; }
        PreparedStatement pstmt = null;
    	try {
			pstmt = con.prepareStatement(ADD_ITEM);
            boolean hasBatchItems = false;
            for ( final RetryWrapper wrappedItem : addItems)
            {
                hasBatchItems = true;
                final PublishedItem item = wrappedItem.get();
                pstmt.setString(1, item.getNode().getService().getServiceID());
                pstmt.setString(2, encodeNodeID(item.getNodeID()));
                pstmt.setString(3, item.getID());
                pstmt.setString(4, item.getPublisher().toString());
                pstmt.setString(5, StringUtils.dateToMillis(item.getCreationDate()));
                pstmt.setString(6, item.getPayloadXML());
                if (batch) { pstmt.addBatch(); }
                else { 
                	try { pstmt.execute(); }
                	catch (SQLException se) {
        	    		// individual item could not be persisted; retry (up to MAX_ITEM_RETRY attempts)
        	    		String itemKey = item.getItemKey();
        	    		if (wrappedItem.nextRetry() < MAX_ITEM_RETRY) {
        	        		log.warn("Failed to persist published item (will retry): " + itemKey);
        	                savePublishedItem(wrappedItem);
        	    		} else {
        	    			// all hope is lost ... item will be dropped
        	    			log.error("Published item could not be written to database: " + itemKey + "\n" + item.getPayloadXML(), se);
        	    		}
                	}
                }
            }
            if (batch && hasBatchItems) { pstmt.executeBatch(); }			
    	} catch (SQLException se) {
			log.error("Failed to persist published items as batch; will retry individually", se);
			// caught by caller; should not cause a transaction rollback
			throw se;
    	} finally {
    		DbConnectionManager.closeStatement(pstmt);
    	}
	}

    @Override
    public void removePublishedItem(PublishedItem item) {
    	String itemKey = item.getItemKey();
        itemCache.remove(itemKey);
        synchronized (itemsPending)
    	{
    		itemsToDelete.addLast(item);
    		itemsPending.remove(itemKey);
		}
    }

    private static String getDefaultNodeConfigurationCacheKey( PubSubService service, boolean isLeafType )
    {
        return service.getServiceID() + "|" + Boolean.toString( isLeafType );
    }

    @Override
    public DefaultNodeConfiguration loadDefaultConfiguration(PubSubService service,
            boolean isLeafType) {

        final String key = getDefaultNodeConfigurationCacheKey( service, isLeafType );
        DefaultNodeConfiguration result = defaultNodeConfigurationCache.get( key );
        if ( result == null )
        {
            final Lock lock = CacheFactory.getLock( DEFAULT_CONF_CACHE, defaultNodeConfigurationCache );
            try
            {
                lock.lock();
                result = defaultNodeConfigurationCache.get( key );
                if ( result == null )
                {
                    Connection con = null;
                    PreparedStatement pstmt = null;
                    ResultSet rs = null;
                    DefaultNodeConfiguration config = null;
                    try {
                        con = DbConnectionManager.getConnection();
                        // Get default node configuration for the specified service
                        pstmt = con.prepareStatement(LOAD_DEFAULT_CONF);
                        pstmt.setString(1, service.getServiceID());
                        pstmt.setInt(2, (isLeafType ? 1 : 0));
                        rs = pstmt.executeQuery();
                        if (rs.next()) {
                            config = new DefaultNodeConfiguration(isLeafType);
                            // Rebuild loaded default node configuration
                            config.setDeliverPayloads(rs.getInt(1) == 1);
                            config.setMaxPayloadSize(rs.getInt(2));
                            config.setPersistPublishedItems(rs.getInt(3) == 1);
                            config.setMaxPublishedItems(rs.getInt(4));
                            config.setNotifyConfigChanges(rs.getInt(5) == 1);
                            config.setNotifyDelete(rs.getInt(6) == 1);
                            config.setNotifyRetract(rs.getInt(7) == 1);
                            config.setPresenceBasedDelivery(rs.getInt(8) == 1);
                            config.setSendItemSubscribe(rs.getInt(9) == 1);
                            config.setPublisherModel(PublisherModel.valueOf(rs.getString(10)));
                            config.setSubscriptionEnabled(rs.getInt(11) == 1);
                            config.setAccessModel(AccessModel.valueOf(rs.getString(12)));
                            config.setLanguage(rs.getString(13));
                            if (rs.getString(14) != null) {
                                config.setReplyPolicy(Node.ItemReplyPolicy.valueOf(rs.getString(14)));
                            }
                            config.setAssociationPolicy(
                                    CollectionNode.LeafNodeAssociationPolicy.valueOf(rs.getString(15)));
                            config.setMaxLeafNodes(rs.getInt(16));
                        }
                        defaultNodeConfigurationCache.put( key, config );
                        result = config;
                    }
                    catch (Exception sqle) {
                        log.error(sqle.getMessage(), sqle);
                    }
                    finally {
                        DbConnectionManager.closeConnection(rs, pstmt, con);
                    }
                }
            }
            finally
            {
                lock.unlock();
            }
        }
        return result;
    }

    @Override
    public void createDefaultConfiguration(PubSubService service,
            DefaultNodeConfiguration config) {

        final String key = getDefaultNodeConfigurationCacheKey( service, config.isLeaf() );

        final Lock lock = CacheFactory.getLock( DEFAULT_CONF_CACHE, defaultNodeConfigurationCache );
        try
        {
            lock.lock();

            Connection con = null;
            PreparedStatement pstmt = null;
            try {
                con = DbConnectionManager.getConnection();
                pstmt = con.prepareStatement(ADD_DEFAULT_CONF);
                pstmt.setString(1, service.getServiceID());
                pstmt.setInt(2, (config.isLeaf() ? 1 : 0));
                pstmt.setInt(3, (config.isDeliverPayloads() ? 1 : 0));
                pstmt.setInt(4, config.getMaxPayloadSize());
                pstmt.setInt(5, (config.isPersistPublishedItems() ? 1 : 0));
                pstmt.setInt(6, config.getMaxPublishedItems());
                pstmt.setInt(7, (config.isNotifyConfigChanges() ? 1 : 0));
                pstmt.setInt(8, (config.isNotifyDelete() ? 1 : 0));
                pstmt.setInt(9, (config.isNotifyRetract() ? 1 : 0));
                pstmt.setInt(10, (config.isPresenceBasedDelivery() ? 1 : 0));
                pstmt.setInt(11, (config.isSendItemSubscribe() ? 1 : 0));
                pstmt.setString(12, config.getPublisherModel().getName());
                pstmt.setInt(13, (config.isSubscriptionEnabled() ? 1 : 0));
                pstmt.setString(14, config.getAccessModel().getName());
                pstmt.setString(15, config.getLanguage());
                if (config.getReplyPolicy() != null) {
                    pstmt.setString(16, config.getReplyPolicy().name());
                }
                else {
                    pstmt.setString(16, null);
                }
                pstmt.setString(17, config.getAssociationPolicy().name());
                pstmt.setInt(18, config.getMaxLeafNodes());
                pstmt.executeUpdate();

                defaultNodeConfigurationCache.put( key, config );
            }
            catch (SQLException sqle) {
                log.error(sqle.getMessage(), sqle);
            }
            finally {
                DbConnectionManager.closeConnection(pstmt, con);
            }
        }
        finally
        {
            lock.unlock();
        }
    }

    @Override
    public void updateDefaultConfiguration(PubSubService service,
            DefaultNodeConfiguration config) {

        final Lock lock = CacheFactory.getLock( DEFAULT_CONF_CACHE, defaultNodeConfigurationCache );
        try {
            Connection con = null;
            PreparedStatement pstmt = null;
            try {
                con = DbConnectionManager.getConnection();
                pstmt = con.prepareStatement(UPDATE_DEFAULT_CONF);
                pstmt.setInt(1, (config.isDeliverPayloads() ? 1 : 0));
                pstmt.setInt(2, config.getMaxPayloadSize());
                pstmt.setInt(3, (config.isPersistPublishedItems() ? 1 : 0));
                pstmt.setInt(4, config.getMaxPublishedItems());
                pstmt.setInt(5, (config.isNotifyConfigChanges() ? 1 : 0));
                pstmt.setInt(6, (config.isNotifyDelete() ? 1 : 0));
                pstmt.setInt(7, (config.isNotifyRetract() ? 1 : 0));
                pstmt.setInt(8, (config.isPresenceBasedDelivery() ? 1 : 0));
                pstmt.setInt(9, (config.isSendItemSubscribe() ? 1 : 0));
                pstmt.setString(10, config.getPublisherModel().getName());
                pstmt.setInt(11, (config.isSubscriptionEnabled() ? 1 : 0));
                pstmt.setString(12, config.getAccessModel().getName());
                pstmt.setString(13, config.getLanguage());
                if (config.getReplyPolicy() != null) {
                    pstmt.setString(14, config.getReplyPolicy().name());
                }
                else {
                    pstmt.setString(14, null);
                }
                pstmt.setString(15, config.getAssociationPolicy().name());
                pstmt.setInt(16, config.getMaxLeafNodes());
                pstmt.setString(17, service.getServiceID());
                pstmt.setInt(18, (config.isLeaf() ? 1 : 0));
                pstmt.executeUpdate();


                getDefaultNodeConfigurationCacheKey( service, false );

                // Note that 'isLeaf' might have changed.
                defaultNodeConfigurationCache.remove( getDefaultNodeConfigurationCacheKey( service, true ) );
                defaultNodeConfigurationCache.remove( getDefaultNodeConfigurationCacheKey( service, false ) );
                defaultNodeConfigurationCache.put( getDefaultNodeConfigurationCacheKey( service, config.isLeaf() ), config );
            }
            catch (SQLException sqle) {
                log.error(sqle.getMessage(), sqle);
            }
            finally {
                DbConnectionManager.closeConnection(pstmt, con);
            }
        }
        finally {
            lock.unlock();
        }
    }

    @Override
    public List<PublishedItem> getPublishedItems(LeafNode node) {
    	return getPublishedItems(node, node.getMaxPublishedItems());
    }

    @Override
    public List<PublishedItem> getPublishedItems(LeafNode node, int maxRows) {
        Lock itemLock = CacheFactory.getLock(ITEM_CACHE, itemCache);
        try {
	    	// NOTE: force other requests to wait for DB I/O to complete
        	itemLock.lock();
	    	flushPendingItems( node.getUniqueIdentifier() );
        } finally {
        	itemLock.unlock();
        }
    	Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        int max = MAX_ROWS_FETCH;
        int maxPublished = node.getMaxPublishedItems();

        // Limit the max rows until a solution is in place with Result Set Management
        if (maxRows != -1)
        	max = maxPublished == -1 ? Math.min(maxRows, MAX_ROWS_FETCH) :  Math.min(maxRows, maxPublished);
        else if (maxPublished != -1)
        	max = Math.min(MAX_ROWS_FETCH, maxPublished);

        // We don't know how many items are in the db, so we will start with an allocation of 500
		java.util.LinkedList<PublishedItem> results = new java.util.LinkedList<>();
		boolean descending = JiveGlobals.getBooleanProperty("xmpp.pubsub.order.descending", false);

		try
		{
            con = DbConnectionManager.getConnection();
            // Get published items of the specified node
            pstmt = con.prepareStatement(LOAD_ITEMS);
            pstmt.setMaxRows(max);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            rs = pstmt.executeQuery();
            int counter = 0;

            // Rebuild loaded published items
            while(rs.next() && (counter < max)) {
                String itemID = rs.getString(1);
                JID publisher = new JID(rs.getString(2));
                Date creationDate = new Date(Long.parseLong(rs.getString(3).trim()));
                // Create the item
                PublishedItem item = new PublishedItem(node, publisher, itemID, creationDate);
                // Add the extra fields to the published item
                if (rs.getString(4) != null) {
                	item.setPayloadXML(rs.getString(4));
                }
                // Add the published item to the node
				if (descending)
					results.add(item);
				else
					results.addFirst(item);
                counter++;
            }
        }
        catch (Exception sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }

        return results;
    }

    @Override
    public PublishedItem getLastPublishedItem(LeafNode node) {
        Lock itemLock = CacheFactory.getLock(ITEM_CACHE, itemCache);
        try {
        	// NOTE: force other requests to wait for DB I/O to complete
        	itemLock.lock();
	    	flushPendingItems();
        } finally {
        	itemLock.unlock();
        }
        Connection con = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PublishedItem item = null;

        try {
            con = DbConnectionManager.getConnection();
            // Get published items of the specified node
            pstmt = con.prepareStatement(LOAD_LAST_ITEM);
            pstmt.setFetchSize(1);
            pstmt.setMaxRows(1);
            pstmt.setString(1, node.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(node.getNodeID()));
            rs = pstmt.executeQuery();
            // Rebuild loaded published items
            if (rs.next()) {
                String itemID = rs.getString(1);
                JID publisher = new JID(rs.getString(2));
                Date creationDate = new Date(Long.parseLong(rs.getString(3).trim()));
                // Create the item
                item = new PublishedItem(node, publisher, itemID, creationDate);
                // Add the extra fields to the published item
                if (rs.getString(4) != null) {
                	item.setPayloadXML(rs.getString(4));
                }
            }
        }
        catch (Exception sqle) {
            log.error(sqle.getMessage(), sqle);
        }
        finally {
            DbConnectionManager.closeConnection(rs, pstmt, con);
        }
        return item;
    }

    @Override
    public PublishedItem getPublishedItem(LeafNode node, String itemID) {
    	String itemKey = PublishedItem.getItemKey(node, itemID);

        // try to fetch from cache first without locking
        PublishedItem result = itemCache.get(itemKey);
    	if (result == null) {
            Lock itemLock = CacheFactory.getLock(ITEM_CACHE, itemCache);
            try {
    	    	// Acquire lock, then re-check cache before reading from DB;
            	// allows clustered item cache to be primed by first request
            	itemLock.lock();
            	result = itemCache.get(itemKey);
            	if (result == null) {
	            	flushPendingItems(); 
	
	        		// fetch item from DB
	                Connection con = null;
	                PreparedStatement pstmt = null;
	                ResultSet rs = null;
	                try {
	                    con = DbConnectionManager.getConnection();
	                    pstmt = con.prepareStatement(LOAD_ITEM);
	                    pstmt.setString(1, node.getService().getServiceID());
	                    pstmt.setString(2, node.getNodeID());
	                    pstmt.setString(3, itemID);
	                    rs = pstmt.executeQuery();
	
	                    // Add to each node the corresponding subscriptions
	                    if (rs.next()) {
	                        JID publisher = new JID(rs.getString(1));
	                        Date creationDate = new Date(Long.parseLong(rs.getString(2).trim()));
	                        // Create the item
	                        result = new PublishedItem(node, publisher, itemID, creationDate);
	                        // Add the extra fields to the published item
	                        if (rs.getString(3) != null) {
	                        	result.setPayloadXML(rs.getString(3));
	                        }
	                        itemCache.put(itemKey, result);
	                		log.debug("Loaded item into cache from DB");
	                    }
	                } catch (Exception exc) {
	                    log.error(exc.getMessage(), exc);
	                } finally {
	                    DbConnectionManager.closeConnection(pstmt, con);
	                }
            	} else {
            		log.debug("Found cached item on second attempt (after acquiring lock)");
            	}
            } finally {
            	itemLock.unlock();
            }
    	} else {
    		log.debug("Found cached item on first attempt (no lock)");
    	}
        return result;
	}

	@Override
	public void purgeNode(LeafNode leafNode)
	{
		Connection con = null;
		boolean rollback = false;

		try
		{
			con = DbConnectionManager.getTransactionConnection();

			purgeNode(leafNode, con);
		}
		catch (SQLException exc)
		{
			log.error(exc.getMessage(), exc);
			rollback = true;
		}
		finally
		{
			DbConnectionManager.closeTransactionConnection(con, rollback);
		}
	}

	private void purgeNode(LeafNode leafNode, Connection con) throws SQLException
	{
	    // If there are any pending items for this node, don't bother processing them.
        synchronized (itemsPending) {
            itemsPending.values().removeIf( retryWrapper -> leafNode.getUniqueIdentifier().equals( retryWrapper.get().getNode().getUniqueIdentifier() ) );
            itemsToAdd.removeIf( retryWrapper -> leafNode.getUniqueIdentifier().equals( retryWrapper.get().getNode().getUniqueIdentifier() ) );
            itemsToDelete.removeIf( publishedItem -> leafNode.getUniqueIdentifier().equals( publishedItem.getNode().getUniqueIdentifier() ) );
        }

        // Remove published items of the node being deleted
        PreparedStatement pstmt = null;

		try
		{
            pstmt = con.prepareStatement(DELETE_ITEMS);
            pstmt.setString(1, leafNode.getService().getServiceID());
            pstmt.setString(2, encodeNodeID(leafNode.getNodeID()));
            pstmt.executeUpdate();
		}
		finally
		{
			DbConnectionManager.closeStatement(pstmt);
		}

		// drop cached items for purged node
		synchronized (itemCache)
		{
			for (PublishedItem item : itemCache.values())
			{
				if (leafNode.getUniqueIdentifier().equals(item.getNode().getUniqueIdentifier()))
				{
					itemCache.remove(item.getItemKey());
				}
            }
		}
	}

	private static String encodeWithComma(Collection<String> strings) {
        StringBuilder sb = new StringBuilder(90);
        for (String group : strings) {
            sb.append(group).append(',');
        }
        if (!strings.isEmpty()) {
            sb.setLength(sb.length()-1);
        }
        else {
            // Add a blank so an empty string is never replaced with NULL (oracle...arggg!!!)
            sb.append(' ');
        }
        return sb.toString();
    }

    private static Collection<String> decodeWithComma(String strings) {
        Collection<String> decodedStrings = new ArrayList<>();
        StringTokenizer tokenizer = new StringTokenizer(strings.trim(), ",");
        while (tokenizer.hasMoreTokens()) {
            decodedStrings.add(tokenizer.nextToken());
        }
        return decodedStrings;
    }

    private static String encodeNodeID(String nodeID) {
        if (DbConnectionManager.getDatabaseType() == DbConnectionManager.DatabaseType.oracle &&
                "".equals(nodeID)) {
            // Oracle stores empty strings as null so return a string with a space
            return " ";
        }
        return nodeID;
    }

    private static String decodeNodeID(String nodeID) {
        if (DbConnectionManager.getDatabaseType() == DbConnectionManager.DatabaseType.oracle &&
                " ".equals(nodeID)) {
            // Oracle stores empty strings as null so convert them back to empty strings
            return "";
        }
        return nodeID;
    }

    /**
     * Purges all items from the database that exceed the defined item count on
     * all nodes.
     */
    private void purgeItems()
    {
		boolean abortTransaction = false;
        Connection con = null;
        PreparedStatement pstmt = null;
		PreparedStatement nodeConfig = null;
        ResultSet rs = null;

        try
        {
            con = DbConnectionManager.getTransactionConnection();
			nodeConfig = con.prepareStatement(PERSISTENT_NODES);
            rs = nodeConfig.executeQuery();
			PreparedStatement purgeNode = con
					.prepareStatement(getPurgeStatement(DbConnectionManager.getDatabaseType()));

            Boolean hasBatchItems = false;
            while (rs.next())
            {
                hasBatchItems = true;
            	String svcId = rs.getString(1);
            	String nodeId = rs.getString(2);
            	int maxItems = rs.getInt(3);

				setPurgeParams(DbConnectionManager.getDatabaseType(), purgeNode, svcId, nodeId, maxItems);

				purgeNode.addBatch();
            }
			if (hasBatchItems) purgeNode.executeBatch();
		}
		catch (Exception sqle)
		{
		    log.error(sqle.getMessage(), sqle);
			abortTransaction = true;
		}
		finally
		{
			DbConnectionManager.closeResultSet(rs);
			DbConnectionManager.closeStatement(rs, nodeConfig);
			DbConnectionManager.closeTransactionConnection(pstmt, con, abortTransaction);
		}
    }

	private static void setPurgeParams(DatabaseType dbType, PreparedStatement purgeStmt, String serviceId,
			String nodeId, int maxItems) throws SQLException
	{
		switch (dbType)
		{
		case hsqldb:
			purgeStmt.setString(1, serviceId);
			purgeStmt.setString(2, nodeId);
			purgeStmt.setString(3, serviceId);
			purgeStmt.setString(4, nodeId);
			purgeStmt.setInt(5, maxItems);
			break;

		default:
			purgeStmt.setString(1, serviceId);
			purgeStmt.setString(2, nodeId);
			purgeStmt.setInt(3, maxItems);
			purgeStmt.setString(4, serviceId);
			purgeStmt.setString(5, nodeId);
			break;
		}
	}

	private static String getPurgeStatement(DatabaseType type)
	{
		switch (type)
		{
		case postgresql:
			return PURGE_FOR_SIZE_POSTGRESQL;
		case mysql:
			return PURGE_FOR_SIZE_MYSQL;
		case hsqldb:
			return PURGE_FOR_SIZE_HSQLDB;

		default:
			return PURGE_FOR_SIZE;
		}
	}

	@Override
    public void shutdown()
    {
    	log.info("Flushing write cache to database");
		flushPendingItems(false); // local member only
		
		// node cleanup (skip when running as a cluster)
		if (!ClusterManager.isClusteringEnabled()) {
			purgeItems();
		}
    }
}
