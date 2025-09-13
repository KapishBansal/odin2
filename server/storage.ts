import { 
  type User, 
  type InsertUser,
  type Mission,
  type InsertMission,
  type SpaceWeather,
  type InsertSpaceWeather,
  type ThreatEvent,
  type InsertThreatEvent,
  type AiDecision,
  type InsertAiDecision,
  type Trajectory,
  type InsertTrajectory,
  users,
  missions,
  spaceWeather,
  threatEvents,
  aiDecisions,
  trajectories
} from "@shared/schema";
import { db } from "./db";
import { eq, and, desc, gte, lte, or } from "drizzle-orm";
import bcrypt from "bcrypt";

// ODIN System Storage Interface
export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  verifyPassword(username: string, password: string): Promise<User | null>;

  // Missions
  getMission(id: string): Promise<Mission | undefined>;
  getMissionByMissionId(missionId: string): Promise<Mission | undefined>;
  getAllMissions(): Promise<Mission[]>;
  getActiveMissions(): Promise<Mission[]>;
  createMission(mission: InsertMission): Promise<Mission>;
  updateMission(id: string, updates: Partial<Mission>): Promise<Mission | undefined>;
  deleteMission(id: string): Promise<boolean>;

  // Space Weather Data
  getSpaceWeatherByTimeRange(startTime: Date, endTime: Date): Promise<SpaceWeather[]>;
  getLatestSpaceWeather(): Promise<SpaceWeather | undefined>;
  createSpaceWeather(data: InsertSpaceWeather): Promise<SpaceWeather>;

  // Threat Events
  getThreatEvent(id: string): Promise<ThreatEvent | undefined>;
  getThreatEventsByMission(missionId: string): Promise<ThreatEvent[]>;
  getActiveThreatEvents(): Promise<ThreatEvent[]>;
  createThreatEvent(event: InsertThreatEvent): Promise<ThreatEvent>;
  updateThreatEvent(id: string, updates: Partial<ThreatEvent>): Promise<ThreatEvent | undefined>;
  resolveThreatEvent(id: string): Promise<boolean>;

  // AI Decisions
  getAiDecision(id: string): Promise<AiDecision | undefined>;
  getAiDecisionsByMission(missionId: string): Promise<AiDecision[]>;
  getAllAiDecisions(): Promise<AiDecision[]>;
  createAiDecision(decision: InsertAiDecision): Promise<AiDecision>;
  updateAiDecision(id: string, updates: Partial<AiDecision>): Promise<AiDecision | undefined>;

  // Trajectories
  getTrajectory(id: string): Promise<Trajectory | undefined>;
  getTrajectoriesByMission(missionId: string): Promise<Trajectory[]>;
  getActiveTrajectoryForMission(missionId: string): Promise<Trajectory | undefined>;
  createTrajectory(trajectory: InsertTrajectory): Promise<Trajectory>;
  updateTrajectory(id: string, updates: Partial<Trajectory>): Promise<Trajectory | undefined>;
  setActiveTrajectory(missionId: string, trajectoryId: string): Promise<boolean>;
}

export class PostgresStorage implements IStorage {
  // Users
  async getUser(id: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return result[0];
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.username, username)).limit(1);
    return result[0];
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    // Hash password before storing
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(insertUser.password, saltRounds);
    
    const userWithHashedPassword = {
      ...insertUser,
      password: hashedPassword
    };
    
    const result = await db.insert(users).values(userWithHashedPassword).returning();
    return result[0];
  }

  async verifyPassword(username: string, password: string): Promise<User | null> {
    const user = await this.getUserByUsername(username);
    if (!user) {
      return null;
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? user : null;
  }

  // Missions
  async getMission(id: string): Promise<Mission | undefined> {
    const result = await db.select().from(missions).where(eq(missions.id, id)).limit(1);
    return result[0];
  }

  async getMissionByMissionId(missionId: string): Promise<Mission | undefined> {
    const result = await db.select().from(missions).where(eq(missions.missionId, missionId)).limit(1);
    return result[0];
  }

  async getAllMissions(): Promise<Mission[]> {
    return await db.select().from(missions).orderBy(desc(missions.createdAt));
  }

  async getActiveMissions(): Promise<Mission[]> {
    return await db.select().from(missions)
      .where(or(eq(missions.status, "active"), eq(missions.status, "planning")))
      .orderBy(desc(missions.createdAt));
  }

  async createMission(mission: InsertMission): Promise<Mission> {
    const result = await db.insert(missions).values(mission).returning();
    return result[0];
  }

  async updateMission(id: string, updates: Partial<Mission>): Promise<Mission | undefined> {
    const result = await db.update(missions)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(missions.id, id))
      .returning();
    return result[0];
  }

  async deleteMission(id: string): Promise<boolean> {
    const result = await db.delete(missions).where(eq(missions.id, id)).returning();
    return result.length > 0;
  }

  // Space Weather Data
  async getSpaceWeatherByTimeRange(startTime: Date, endTime: Date): Promise<SpaceWeather[]> {
    return await db.select().from(spaceWeather)
      .where(and(
        gte(spaceWeather.timestamp, startTime),
        lte(spaceWeather.timestamp, endTime)
      ))
      .orderBy(desc(spaceWeather.timestamp));
  }

  async getLatestSpaceWeather(): Promise<SpaceWeather | undefined> {
    const result = await db.select().from(spaceWeather)
      .orderBy(desc(spaceWeather.timestamp))
      .limit(1);
    return result[0];
  }

  async createSpaceWeather(data: InsertSpaceWeather): Promise<SpaceWeather> {
    const result = await db.insert(spaceWeather).values(data).returning();
    return result[0];
  }

  // Threat Events
  async getThreatEvent(id: string): Promise<ThreatEvent | undefined> {
    const result = await db.select().from(threatEvents).where(eq(threatEvents.id, id)).limit(1);
    return result[0];
  }

  async getThreatEventsByMission(missionId: string): Promise<ThreatEvent[]> {
    return await db.select().from(threatEvents)
      .where(eq(threatEvents.missionId, missionId))
      .orderBy(desc(threatEvents.detectedAt));
  }

  async getActiveThreatEvents(): Promise<ThreatEvent[]> {
    return await db.select().from(threatEvents)
      .where(eq(threatEvents.status, "active"))
      .orderBy(desc(threatEvents.detectedAt));
  }

  async createThreatEvent(event: InsertThreatEvent): Promise<ThreatEvent> {
    const result = await db.insert(threatEvents).values(event).returning();
    return result[0];
  }

  async updateThreatEvent(id: string, updates: Partial<ThreatEvent>): Promise<ThreatEvent | undefined> {
    const result = await db.update(threatEvents)
      .set(updates)
      .where(eq(threatEvents.id, id))
      .returning();
    return result[0];
  }

  async resolveThreatEvent(id: string): Promise<boolean> {
    const result = await db.update(threatEvents)
      .set({ status: "resolved", resolvedAt: new Date() })
      .where(eq(threatEvents.id, id))
      .returning();
    return result.length > 0;
  }

  // AI Decisions
  async getAiDecision(id: string): Promise<AiDecision | undefined> {
    const result = await db.select().from(aiDecisions).where(eq(aiDecisions.id, id)).limit(1);
    return result[0];
  }

  async getAiDecisionsByMission(missionId: string): Promise<AiDecision[]> {
    return await db.select().from(aiDecisions)
      .where(eq(aiDecisions.missionId, missionId))
      .orderBy(desc(aiDecisions.timestamp));
  }

  async getAllAiDecisions(): Promise<AiDecision[]> {
    return await db.select().from(aiDecisions).orderBy(desc(aiDecisions.timestamp));
  }

  async createAiDecision(decision: InsertAiDecision): Promise<AiDecision> {
    const result = await db.insert(aiDecisions).values(decision).returning();
    return result[0];
  }

  async updateAiDecision(id: string, updates: Partial<AiDecision>): Promise<AiDecision | undefined> {
    const result = await db.update(aiDecisions)
      .set(updates)
      .where(eq(aiDecisions.id, id))
      .returning();
    return result[0];
  }

  // Trajectories
  async getTrajectory(id: string): Promise<Trajectory | undefined> {
    const result = await db.select().from(trajectories).where(eq(trajectories.id, id)).limit(1);
    return result[0];
  }

  async getTrajectoriesByMission(missionId: string): Promise<Trajectory[]> {
    return await db.select().from(trajectories)
      .where(eq(trajectories.missionId, missionId))
      .orderBy(desc(trajectories.createdAt));
  }

  async getActiveTrajectoryForMission(missionId: string): Promise<Trajectory | undefined> {
    const result = await db.select().from(trajectories)
      .where(and(
        eq(trajectories.missionId, missionId),
        eq(trajectories.isActive, true)
      ))
      .limit(1);
    return result[0];
  }

  async createTrajectory(trajectory: InsertTrajectory): Promise<Trajectory> {
    const result = await db.insert(trajectories).values(trajectory).returning();
    return result[0];
  }

  async updateTrajectory(id: string, updates: Partial<Trajectory>): Promise<Trajectory | undefined> {
    const result = await db.update(trajectories)
      .set(updates)
      .where(eq(trajectories.id, id))
      .returning();
    return result[0];
  }

  async setActiveTrajectory(missionId: string, trajectoryId: string): Promise<boolean> {
    // Use transaction to prevent race conditions
    const result = await db.transaction(async (tx) => {
      // First, deactivate all trajectories for this mission
      await tx.update(trajectories)
        .set({ isActive: false })
        .where(eq(trajectories.missionId, missionId));
      
      // Then activate the selected trajectory
      const updateResult = await tx.update(trajectories)
        .set({ isActive: true })
        .where(and(
          eq(trajectories.id, trajectoryId),
          eq(trajectories.missionId, missionId)
        ))
        .returning();
      
      return updateResult.length > 0;
    });
    
    return result;
  }
}

export const storage = new PostgresStorage();
