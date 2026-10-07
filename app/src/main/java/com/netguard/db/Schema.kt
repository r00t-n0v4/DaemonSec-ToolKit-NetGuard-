package com.netguard.db

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Entity
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.Serializable

@Serializable
@Entity(tableName = "findings")
data class FindingEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: String,
    val type: String,
    val payloadJson: String,
    val flagged: Boolean,
    val timestamp: Long
)

@Serializable
@Entity(tableName = "sessions")
data class SessionEntity(
    @PrimaryKey val id: String,
    val startedAt: Long,
    val scopeDeclaration: String,
    val label: String,
    val endedAt: Long? = null
)

@Dao
interface FindingDao {
    @Insert
    suspend fun insert(finding: FindingEntity): Long

    @Query("SELECT * FROM findings WHERE sessionId = :sessionId ORDER BY timestamp DESC, id DESC")
    fun observeForSession(sessionId: String): Flow<List<FindingEntity>>

    @Query("SELECT * FROM findings WHERE sessionId = :sessionId ORDER BY timestamp ASC, id ASC")
    suspend fun getForSession(sessionId: String): List<FindingEntity>

    @Query("SELECT * FROM findings WHERE sessionId = :sessionId AND type = 'HOST' AND timestamp > :since ORDER BY timestamp ASC")
    suspend fun newHostsSince(sessionId: String, since: Long): List<FindingEntity>

    @Query("DELETE FROM findings WHERE sessionId = :sessionId")
    suspend fun deleteForSession(sessionId: String): Int
}

@Dao
interface SessionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(session: SessionEntity)

    @Query("UPDATE sessions SET endedAt = :endedAt WHERE id = :id")
    suspend fun markEnded(id: String, endedAt: Long)

    @Query("SELECT * FROM sessions ORDER BY startedAt DESC")
    fun observeAll(): Flow<List<SessionEntity>>

    @Query("SELECT * FROM sessions WHERE id = :id")
    suspend fun getById(id: String): SessionEntity?

    /** Latest session that ended before this one — used for "what's new" diffing in reports. */
    @Query("SELECT * FROM sessions WHERE startedAt < :startedAt ORDER BY startedAt DESC LIMIT 1")
    suspend fun previousBefore(startedAt: Long): SessionEntity?

    @Query("DELETE FROM sessions WHERE id = :id")
    suspend fun deleteById(id: String)
}

@Database(entities = [FindingEntity::class, SessionEntity::class], version = 1, exportSchema = false)
abstract class NetGuardDatabase : RoomDatabase() {
    abstract fun findingDao(): FindingDao
    abstract fun sessionDao(): SessionDao

    companion object {
        @Volatile
        private var instance: NetGuardDatabase? = null

        fun getInstance(context: Context): NetGuardDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    NetGuardDatabase::class.java,
                    "netguard.db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                    .also { instance = it }
            }
    }
}